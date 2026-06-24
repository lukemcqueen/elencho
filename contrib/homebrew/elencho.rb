# typed: false
# frozen_string_literal: true

class Elencho < Formula
  desc "Supply-chain malware and obfuscation scanner"
  homepage "https://github.com/lukemcqueen/elencho"
  license "MIT"
  version "0.2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.2.0/elencho-darwin-arm64"
      sha256 "5050387a4c7058968df17d8a2e403ed33225c599fb53358a88e24c8ea030089d"
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.2.0/elencho-darwin-amd64"
      sha256 "2950eefab0f1af7f9afe3544b7350454ea8b6883729b5c60695bec202084f933"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.2.0/elencho-linux-arm64"
      sha256 "12742f776c4707d9568be32df8c49a63bf61fc2f35a48d75bfa71d0f2e5d861e"
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.2.0/elencho-linux-amd64"
      sha256 "ff32c07c01e4a549c5cabeb06fa8c407dd1ed3d4ca50b850f59b169c92254d2a"
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
