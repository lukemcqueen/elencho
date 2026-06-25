# typed: false
# frozen_string_literal: true

class Elencho < Formula
  desc "Supply-chain malware and obfuscation scanner"
  homepage "https://github.com/lukemcqueen/elencho"
  license "MIT"
  version "0.4.2"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.2/elencho-darwin-arm64"
      sha256 "79f528c3ea35312beb603a5307c9b22b966dd328eda2a4b0250c277ec2027292"
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.2/elencho-darwin-amd64"
      sha256 "40c752e452abacbf637b930ca676e68368bd5e181edda5dc321c3c7a098c0a93"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.2/elencho-linux-arm64"
      sha256 "a1dc754372c9ff78aaa36216b367fc3bd7ee696d3a8dc0813f399768ed271c4d"
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.2/elencho-linux-amd64"
      sha256 "e72efa58eeb0b112dc96fa35661737a6b72b6b021fe278f144671e6ead4a8dfe"
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
