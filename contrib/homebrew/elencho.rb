# typed: false
# frozen_string_literal: true

class Elencho < Formula
  desc "Supply-chain malware and obfuscation scanner"
  homepage "https://github.com/lukemcqueen/elencho"
  license "MIT"
  version "0.4.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.0/elencho-darwin-arm64"
      sha256 "2e1bbff917e6cec86558e7256651fb797ca3144d80d8ee37133e114c66d5bb87"
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.0/elencho-darwin-amd64"
      sha256 "ede5468fe8500a9a784b899700d0dae66a316a9922ccf7c749b11bb54f2d1762"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.0/elencho-linux-arm64"
      sha256 "7aef6740a0351d1b54ae35527c16ed12bb7ce37161afc5d2804d41b9099e48bf"
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.0/elencho-linux-amd64"
      sha256 "40efcd168ca129b5876f18aa920baf652070bd98872d2e8b190807386b2ec4c2"
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
