# typed: false
# frozen_string_literal: true

class Elencho < Formula
  desc "Supply-chain malware and obfuscation scanner"
  homepage "https://github.com/lukemcqueen/elencho"
  license "MIT"
  version "0.1.0-dev"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/lukemcqueen/elencho/releases/download/v#{version}/elencho-darwin-arm64"
      sha256 "DEADBEEF" # Replace with actual SHA256 after first release
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v#{version}/elencho-darwin-amd64"
      sha256 "DEADBEEF" # Replace with actual SHA256 after first release
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/lukemcqueen/elencho/releases/download/v#{version}/elencho-linux-arm64"
      sha256 "DEADBEEF" # Replace with actual SHA256 after first release
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v#{version}/elencho-linux-amd64"
      sha256 "DEADBEEF" # Replace with actual SHA256 after first release
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
