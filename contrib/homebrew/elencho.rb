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
      sha256 "bbccf2dcf7c435167f8e8d43b759eddda0fa522c6d19e4f1a3bb05fd83ff2f36"
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.0/elencho-darwin-amd64"
      sha256 "894813b11a208deb54bcab20d9a9d345db7539076d070af2f68981766f5e24e6"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.0/elencho-linux-arm64"
      sha256 "9082b10d6d226b1692350786fe86278686bd996d8a81bc828f91b5a36569c245"
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.0/elencho-linux-amd64"
      sha256 "bbc0e5fc21f09422187637c0b6fd000aeeb367d839b94f4391b78f78c5836279"
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
