# typed: false
# frozen_string_literal: true

class Elencho < Formula
  desc "Supply-chain malware and obfuscation scanner"
  homepage "https://github.com/lukemcqueen/elencho"
  license "MIT"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.1.0/elencho-darwin-arm64"
      sha256 "17c85f62c1be0c2a7654caa637caa67e10ff40aef33bfdea1501f223ff86d1e9"
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.1.0/elencho-darwin-amd64"
      sha256 "b4af0977af688023906967563f82651eb2a4abb05057ccf50b2fdcc823eddbd9"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.1.0/elencho-linux-arm64"
      sha256 "b2c4039233a26db897c69972e00b58e8b9d792f89186961a8121dd22510f7698"
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.1.0/elencho-linux-amd64"
      sha256 "0f24aaf16359e595d1e24e8fec20958f35ea130692f4196d6ee60cadc696b561"
    end
  end

  def install
    bin.install Dir["elencho-*"].first => "elencho"
  end

  test do
    assert_match "elencho #{version}", shell_output("#{bin}/elencho --version")
    assert_match "Available rules:", shell_output("#{bin}/elencho --list-rules")
  end
end
