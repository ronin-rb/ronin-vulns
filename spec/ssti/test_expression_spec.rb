require 'spec_helper'
require 'ronin/vulns/ssti/test_expression'

describe Ronin::Vulns::SSTI::TestExpression do
  let(:string) { '7*7' }
  let(:result) { '49'  }

  subject { described_class.new(string,result) }

  describe "#initialize" do
    it "must set #string" do
      expect(subject.string).to eq(string)
    end

    it "must set #result" do
      expect(subject.result).to eq(result)
    end
  end

  describe "#to_s" do
    it "must return #string" do
      expect(subject.to_s).to eq(string)
    end
  end
end
