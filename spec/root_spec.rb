require 'spec_helper'
require 'ronin/vulns/root'

describe 'Ronin::Vulns::ROOT' do
  subject { Ronin::Vulns::ROOT }

  it "must be a directory" do
    expect(File.directory?(subject)).to be(true)
  end

  it "must be the root directory" do
    expect(subject).to eq(File.expand_path(File.join(__dir__,'..')))
  end
end
