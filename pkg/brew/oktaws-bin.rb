class OktawsBin < Formula
  version '0.10.0'
  desc "Generates temporary AWS credentials with Okta."
  homepage "https://github.com/jonathanmorley/oktaws"

  if OS.mac?
      url "https://github.com/jonathanmorley/oktaws/releases/download/#{version}/oktaws-#{version}-x86_64-apple-darwin.tar.gz"
  elsif OS.linux?
      url "https://github.com/jonathanmorley/oktaws/releases/download/#{version}/oktaws-#{version}-x86_64-unknown-linux-musl.tar.gz"
  end

  def install
    bin.install "oktaws"

    bash_completion.install "complete/oktaws.bash"
    fish_completion.install "complete/oktaws.fish"
    zsh_completion.install "complete/_oktaws"
  end
end
