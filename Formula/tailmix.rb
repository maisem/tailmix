class Tailmix < Formula
  desc "Connect one host to multiple Tailscale tailnets"
  homepage "https://github.com/maisem/tailmix"
  license "BSD-3-Clause"
  head "ssh://git@github.com/maisem/tailmix.git", branch: "main"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args, "./cmd/tailmix"
    system "go", "build", *std_go_args(output: bin/"tailmixd"), "./cmd/tailmixd"
  end

  service do
    run [opt_bin/"tailmixd", "-state", var/"lib/tailmix/state.json"]
    keep_alive true
    require_root true
    log_path var/"log/tailmixd.log"
    error_log_path var/"log/tailmixd.log"
  end

  test do
    assert_match "tailmix manages multiple Tailscale profiles", shell_output("#{bin}/tailmix help")
    assert_match "Usage of tailmixd:", shell_output("#{bin}/tailmixd -h 2>&1")
  end
end
