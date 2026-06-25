# typed: false
# frozen_string_literal: true

class Elencho < Formula
  desc "Supply-chain malware and obfuscation scanner"
  homepage "https://github.com/lukemcqueen/elencho"
  license "MIT"
  version "0.4.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.1/elencho-darwin-arm64"
      sha256 "f28d7bb32f4e886a820bb02fd10c0d7c69561884b32519baab8dafbacd7dffde"
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.1/elencho-darwin-amd64"
      sha256 "af2495071bb7156809eba8793c1c4fa0905f656b681eb35d153f7d918202449b"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.1/elencho-linux-arm64"
      sha256 "0007efe11d5462be89b3f0536cbc65f9c7c2ece1ea6d4b9bf0532ad570cb9340"
    else
      url "https://github.com/lukemcqueen/elencho/releases/download/v0.4.1/elencho-linux-amd64"
      sha256 "09b739701833943379733a792f7ee7bfd68d38f22978a21c461040a3847becf9"
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
