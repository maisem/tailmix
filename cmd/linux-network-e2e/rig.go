//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const headscale = "ghcr.io/juanfont/headscale:0.29.5@sha256:780ed2f9e85719a2211277433f2c8afb45105d0d25031949a6848a485f9e216d"

var roles = []string{"control", "peer", "client"}

type rig struct {
	runner
	prefix, network, image string
	tmp, binaryDir, root   string
	controlURL             string
	peerIPs                []string
	labels                 []string
	mounts                 []mount
	names                  map[string]string
	pending                []*pending
	containerCaller        bool
	paused, clientStarted  bool
	stage                  string
	out                    io.Writer
}

func newUUID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", failure("random identity unavailable")
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return hex.EncodeToString(id[:]), nil
}

func newRig(ctx context.Context, opts options, out io.Writer) *rig {
	root := os.Getenv("TAILMIX_E2E_ROOT")
	if root == "" {
		root = must(os.Getwd())
	}
	r := &rig{
		runner: runner{ctx},
		root:   must(findRoot(root)),
		prefix: "tailmix-e2e-" + must(newUUID()),
		names:  map[string]string{},
		stage:  "initialization",
		out:    out,
	}
	r.network, r.image = r.prefix+"-net", r.prefix+"-tools"
	for _, role := range roles {
		r.names[role] = r.prefix + "-" + role
	}
	r.labels = must(lifecycleLabels(os.Getenv("TAILMIX_E2E_RUN_ID"), false))
	if _, err := os.Stat("/.dockerenv"); err == nil {
		r.containerCaller = true
		hostname, err := os.ReadFile("/etc/hostname")
		if err != nil {
			hostname = []byte(os.Getenv("HOSTNAME"))
		}
		r.mounts = must(ownContainerMounts(func(name string) result {
			return r.docker(false, 15*time.Second, "inspect", "--type", "container", name)
		}, os.Getenv("HOSTNAME"), string(hostname)))
	}
	parent := ""
	if r.containerCaller {
		parent = os.Getenv("RUNNER_TEMP")
		require(parent != "", "shared RUNNER_TEMP required in caller container")
		_ = r.bind(parent)
	}
	if opts.binaryDir != "" {
		_ = r.bind(opts.binaryDir)
	}
	// No allocation until all caller-supplied bind paths have been validated.
	r.tmp = must(os.MkdirTemp(parent, "tailmix-e2e-"))
	if err := os.Chmod(r.tmp, 0o700); err != nil {
		_ = os.RemoveAll(r.tmp)
		panic(failure("private directory permissions"))
	}
	r.binaryDir = filepath.Join(r.tmp, "bin")
	if opts.binaryDir != "" {
		r.binaryDir = must(resolvePath(opts.binaryDir))
	}
	return r
}

func (r *rig) announce(stage string) {
	r.stage = stage
	fmt.Fprintln(r.out, "linux-network: "+stage)
}

func (r *rig) docker(check bool, timeout time.Duration, args ...string) result {
	return must(r.run(command{
		argv: append([]string{"docker"}, args...), timeout: timeout, uncheck: !check,
	}))
}

func (r *rig) d(args ...string) result { return r.docker(true, 15*time.Second, args...) }

func (r *rig) ex(check bool, timeout time.Duration, role string, args ...string) result {
	return r.docker(check, timeout, append([]string{"exec", r.names[role]}, args...)...)
}

func (r *rig) e(role string, args ...string) result {
	return r.ex(true, 15*time.Second, role, args...)
}

func (r *rig) cli(check bool, timeout time.Duration, args ...string) result {
	return r.ex(check, timeout, "client", append([]string{"/bin/tailmix", "--socket-dir=/private/sockets"}, args...)...)
}

func (r *rig) c(args ...string) result { return r.cli(true, 15*time.Second, args...) }

func (r *rig) bind(path string) string { return must(daemonPath(path, r.mounts)) }

func (r *rig) poll(timeout time.Duration, predicate func() bool) {
	previous := r.runner
	ctx, cancel := context.WithTimeout(previous.ctx, timeout)
	defer cancel()
	r.runner = runner{ctx}
	defer func() { r.runner = previous }()
	if err := poll(ctx, timeout, predicate); err != nil {
		panic(err)
	}
}

func decode[T any](res result) T {
	var value T
	require(json.Unmarshal([]byte(res.stdout), &value) == nil, "invalid service response")
	return value
}

func (r *rig) start(role, image string, tun bool, extra, cmd []string) {
	args := append([]string{"create"}, r.labels...)
	args = append(args, "--name", r.names[role], "--network", r.network,
		"--network-alias", role, "--log-driver=none",
		"--mount", "type=bind,src="+r.bind(filepath.Join(r.tmp, role))+",dst=/private")
	if tun {
		args = append(args, "--cap-add=NET_ADMIN", "--device=/dev/net/tun",
			"--sysctl=net.ipv6.conf.all.disable_ipv6=0",
			"--sysctl=net.ipv6.conf.default.disable_ipv6=0")
	}
	args = append(args, extra...)
	args = append(args, image)
	r.d(append(args, cmd...)...)
	r.d("start", r.names[role])
}

func buildEnv() []string {
	env := []string{}
	hasMaxProcs := false
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "CGO_ENABLED=") {
			continue
		}
		hasMaxProcs = hasMaxProcs || strings.HasPrefix(entry, "GOMAXPROCS=")
		env = append(env, entry)
	}
	env = append(env, "CGO_ENABLED=0")
	if !hasMaxProcs {
		env = append(env, "GOMAXPROCS=2")
	}
	return env
}

func (r *rig) setup() {
	r.announce("build isolated tools and binaries")
	if !r.containerCaller {
		_, err := os.Stat("/dev/net/tun")
		require(err == nil, "TUN unavailable")
	}
	r.docker(true, 20*time.Second, "info")
	// Copy SELF into the shared private directory. Its original temporary build
	// path need not be a daemon-visible bind in Docker-outside-of-Docker CI.
	if err := copyCleanupHelper(filepath.Join(r.tmp, "cleanup-helper")); err != nil {
		panic(err)
	}
	if err := privateWrite(filepath.Join(r.tmp, ".tailmix-e2e-owner"), strings.TrimPrefix(r.prefix, "tailmix-e2e-")); err != nil {
		panic(err)
	}
	if r.binaryDir == filepath.Join(r.tmp, "bin") {
		require(os.Mkdir(r.binaryDir, 0o700) == nil, "binary directory creation")
		goTool := os.Getenv("GO")
		if goTool == "" {
			goTool = "go"
		}
		for _, name := range []string{"tailmix", "tailmixd"} {
			_ = must(r.run(command{
				argv: []string{goTool, "build", "-p", "1", "-o", filepath.Join(r.binaryDir, name), "./cmd/" + name},
				dir:  r.root, env: buildEnv(), timeout: 720 * time.Second,
			}))
		}
	}
	for _, name := range []string{"tailmix", "tailmixd"} {
		info, err := os.Stat(filepath.Join(r.binaryDir, name))
		require(err == nil && info.Mode().IsRegular(), "missing binary")
	}
	build := filepath.Join(r.tmp, "build")
	require(os.Mkdir(build, 0o700) == nil, "build directory creation")
	dockerfile := must(os.ReadFile(filepath.Join(r.root, "integration", "linux_network.Dockerfile")))
	require(privateWrite(filepath.Join(build, "Dockerfile"), string(dockerfile)) == nil, "private Dockerfile write")
	// Empty context: never upload the checkout, private keys, or caller files.
	buildArgs := append([]string{"build", "-q"}, r.labels...)
	buildArgs = append(buildArgs, "-t", r.image, build)
	r.docker(true, 240*time.Second, buildArgs...)
	r.docker(true, 120*time.Second, "pull", headscale)
	for _, role := range roles {
		require(os.Mkdir(filepath.Join(r.tmp, role), 0o700) == nil, "private directory creation")
	}
	r.d(append(append([]string{"network", "create"}, r.labels...), r.network)...)
	r.setupControl()
	r.setupPeer()
	r.setupClient()
}

const derpConfig = `regions:
  999:
    regionid: 999
    regioncode: local
    regionname: Isolated
    nodes:
      - name: unused
        regionid: 999
        hostname: localhost
        ipv4: 127.0.0.1
        derpport: 1
`

const controlConfig = `server_url: http://headscale:8080
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
noise:
  private_key_path: /private/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: false
  urls: []
  paths: [/private/derp.yaml]
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: /private/db.sqlite
log:
  level: error
policy:
  mode: file
  path: ""
dns:
  magic_dns: true
  base_domain: isolated.test
  override_local_dns: true
  nameservers:
    global: [100.64.0.1]
    split:
      corp.test: [100.64.0.1]
unix_socket: /private/headscale.sock
unix_socket_permission: "0600"
`

func (r *rig) setupControl() {
	r.announce("fresh private control server")
	args := append([]string{"create"}, r.labels...)
	args = append(args, "--name", r.names["control"], "--network", r.network,
		"--network-alias", "headscale", "--log-driver=none",
		"--mount", "type=bind,src="+r.bind(filepath.Join(r.tmp, "control"))+",dst=/private",
		headscale, "-c", "/private/config.yaml", "serve")
	r.d(args...)
	require(privateWrite(filepath.Join(r.tmp, "control", "derp.yaml"), derpConfig) == nil, "private control config")
	configPath := filepath.Join(r.tmp, "control", "config.yaml")
	require(privateWrite(configPath, controlConfig) == nil, "private control config")
	r.d("start", r.names["control"])
	info := decode[[]struct {
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress string }
		}
	}](r.d("inspect", r.names["control"]))
	require(len(info) == 1, "control endpoint allocation")
	ip := info[0].NetworkSettings.Networks[r.network].IPAddress
	addr, err := netip.ParseAddr(ip)
	require(err == nil && addr.Is4(), "control endpoint allocation")
	r.controlURL = "http://" + ip + ":8080"
	require(privateWrite(configPath, strings.ReplaceAll(controlConfig, "http://headscale:8080", r.controlURL)) == nil, "private control config")
	r.d("restart", r.names["control"])
	r.poll(45*time.Second, func() bool {
		return r.ex(false, 15*time.Second, "control", "headscale", "-c", "/private/config.yaml", "users", "list", "-o", "json").code == 0
	})
	user := decode[struct{ ID json.Number }](r.e("control", "headscale", "-c", "/private/config.yaml", "users", "create", "isolated", "-o", "json"))
	require(user.ID != "", "control user allocation")
	for _, role := range []string{"peer", "client"} {
		key := decode[struct{ Key string }](r.e("control", "headscale", "-c", "/private/config.yaml",
			"preauthkeys", "create", "--user", string(user.ID), "--expiration", "1h", "-o", "json")).Key
		require(key != "" && !strings.ContainsAny(key, "\r\n"), "control key allocation")
		text, name := key+"\n", "authkey"
		if role == "client" {
			text, name = "TEST_AUTHKEY="+key+"\nTS_CONTROL_URL="+r.controlURL+"\nTS_NO_LOGS_NO_SUPPORT=true\n", "env"
		}
		require(privateWrite(filepath.Join(r.tmp, role, name), text) == nil, "private authentication file")
	}
}

const dnsmasqConfig = `port=53
interface=tailscale0
listen-address=100.64.0.1
bind-interfaces
no-resolv
no-hosts
local=/corp.test/
host-record=service.corp.test,192.168.50.42,60
pid-file=/private/dnsmasq.pid
user=root
`

func (r *rig) setupPeer() {
	r.announce("real kernel peer registration")
	r.start("peer", r.image, true, []string{"--env", "TS_NO_LOGS_NO_SUPPORT=true"},
		[]string{"tailscaled", "--tun=tailscale0", "--state=/private/state", "--socket=/private/tailscaled.sock", "--no-logs-no-support"})
	r.poll(45*time.Second, func() bool {
		return r.ex(false, 15*time.Second, "peer", "tailscale", "--socket=/private/tailscaled.sock", "status", "--json").code == 0
	})
	r.ex(true, 40*time.Second, "peer", "tailscale", "--socket=/private/tailscaled.sock", "up",
		"--login-server="+r.controlURL, "--auth-key=file:/private/authkey",
		"--accept-dns=false", "--hostname=resolver", "--netfilter-mode=off")
	peer := decode[tailStatus](r.e("peer", "tailscale", "--socket=/private/tailscaled.sock", "status", "--json"))
	r.peerIPs = peer.Self.TailscaleIPs
	require(contains(r.peerIPs, "100.64.0.1"), "fresh sequential allocator")
	var v4, v6 string
	for _, text := range r.peerIPs {
		ip := must(netip.ParseAddr(text))
		if ip.Is4() {
			v4 = ip.String()
		} else {
			v6 = ip.String()
		}
	}
	require(v4 != "" && v6 != "", "private resolver dual-stack targets")
	config := dnsmasqConfig + fmt.Sprintf(`host-record=proxy.corp.test,%s,%s,60
host-record=proxy4.corp.test,%s,60
host-record=proxy6.corp.test,%s,60
host-record=outage.corp.test,%s,60
cname=alias.corp.test,proxy.corp.test
`, v4, v6, v4, v6, v4)
	require(privateWrite(filepath.Join(r.tmp, "peer", "dnsmasq.conf"), config) == nil, "private resolver config")
	r.e("peer", "dnsmasq", "--conf-file=/private/dnsmasq.conf")
}

func (r *rig) setupClient() {
	r.announce("real checkout daemon registration")
	// --env-file is consumed by the local Docker CLI; only bind sources are
	// translated to daemon paths.
	r.start("client", r.image, true, []string{
		"--env-file", filepath.Join(r.tmp, "client", "env"),
		"--mount", "type=bind,src=" + r.bind(r.binaryDir) + ",dst=/checkout,readonly",
	}, nil)
	r.e("client", "ln", "-s", "/checkout/tailmix", "/bin/tailmix")
	r.d("exec", "-d", r.names["client"], "sh", "-c",
		"echo $$ > /private/app.pid; exec /checkout/tailmixd --mode=tun "+
			"--auto-update=false --state=/private/state.json --socket-dir=/private/sockets "+
			"--profile=id=work,dir=/private/work,hostname=client,auth-key-env=TEST_AUTHKEY "+
			"> /private/daemon.log 2>&1")
	r.clientStarted = true
	r.poll(60*time.Second, r.ready)
}

func (r *rig) ready() bool {
	res := r.cli(false, 15*time.Second, "status", "--json")
	if res.code != 0 {
		return false
	}
	return must(readyStatus(res.stdout))
}

func readyStatus(text string) (bool, error) {
	var status struct {
		Profiles []struct {
			BackendState string
			PeerCount    int
		}
		IPRoutes  struct{ ReconcileError string }
		ExitNodes struct{ ReconcileError string }
	}
	if json.Unmarshal([]byte(text), &status) != nil {
		return false, failure("invalid service response")
	}
	running := len(status.Profiles) == 1 && status.Profiles[0].BackendState == "Running"
	if running && status.IPRoutes.ReconcileError != "" {
		return false, failure("kernel route reconciliation")
	}
	if running && status.ExitNodes.ReconcileError != "" {
		return false, failure("exit route reconciliation")
	}
	return running && status.Profiles[0].PeerCount == 1, nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
