class Tailmix < Formula
  desc "Connect one host to multiple Tailscale tailnets"
  homepage "https://github.com/maisem/tailmix"
  license "BSD-3-Clause"
  head "https://github.com/maisem/tailmix.git", branch: "main"

  depends_on "go" => :build

  def install
    ldflags = Utils.safe_popen_read("go", "run", "./cmd/mkversion").split
    system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/tailmix"
    system "go", "build", *std_go_args(output: bin/"tailmixd", ldflags: ldflags), "./cmd/tailmixd"
    generate_completions_from_executable bin/"tailmix", "completion", shells: [:bash, :zsh, :fish, :pwsh]
  end

  service do
    run [opt_bin/"tailmixd", "-state", var/"lib/tailmix/state.json"]
    keep_alive true
    require_root true
    log_path var/"log/tailmixd.log"
    error_log_path var/"log/tailmixd.log"
  end

  test do
    system bin/"tailmix", "version"
    assert_match "tailmix manages multiple Tailscale profiles", shell_output("#{bin}/tailmix help")
    assert_match "completion __complete --", shell_output("#{bin}/tailmix completion bash")
    assert_match "Usage of tailmixd:", shell_output("#{bin}/tailmixd -h 2>&1")
  end
end
