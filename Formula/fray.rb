class Fray < Formula
  include Language::Python::Virtualenv

  desc "Open-source WAF bypass & security testing toolkit"
  homepage "https://github.com/dalisecurity/fray"
  url "https://files.pythonhosted.org/packages/source/f/fray/fray-3.4.0.tar.gz"
  sha256 "3b2998e08a2521f896c59aea6d86cca854576c6d0f8229cbd3d52a89e35ea78c"
  license "MIT"

  depends_on "python@3.12"

  resource "rich" do
    url "https://files.pythonhosted.org/packages/source/r/rich/rich-13.9.4.tar.gz"
    sha256 ""  # TODO: Update with actual hash
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "fray", shell_output("#{bin}/fray --version")
  end
end
