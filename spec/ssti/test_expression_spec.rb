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

  describe ".parse" do
    subject { described_class }

    context "when given 'X*Z'" do
      let(:string) { '7*7' }
      let(:result) { '49'  }

      it "must parse the string and calculate the result" do
        expr = subject.parse(string)

        expect(expr).to be_kind_of(described_class)
        expect(expr.string).to eq(string)
        expect(expr.result).to eq(result)
      end
    end

    context "when given 'X * Z'" do
      let(:string) { '7 * 7' }
      let(:result) { '49' }

      it "must parse the string and calculate the result" do
        expr = subject.parse(string)

        expect(expr).to be_kind_of(described_class)
        expect(expr.string).to eq(string)
        expect(expr.result).to eq(result)
      end
    end

    context "when given 'X/Z'" do
      let(:string) { '100/50' }
      let(:result) { '2'      }

      it "must parse the string and calculate the result" do
        expr = subject.parse(string)

        expect(expr).to be_kind_of(described_class)
        expect(expr.string).to eq(string)
        expect(expr.result).to eq(result)
      end
    end

    context "when given 'X / Z'" do
      let(:string) { '100 / 50' }
      let(:result) { '2'        }

      it "must parse the string and calculate the result" do
        expr = subject.parse(string)

        expect(expr).to be_kind_of(described_class)
        expect(expr.string).to eq(string)
        expect(expr.result).to eq(result)
      end
    end

    context "when given 'X+Z'" do
      let(:string) { '7+7' }
      let(:result) { '14'  }

      it "must parse the string and calculate the result" do
        expr = subject.parse(string)

        expect(expr).to be_kind_of(described_class)
        expect(expr.string).to eq(string)
        expect(expr.result).to eq(result)
      end
    end

    context "when given 'X + Z'" do
      let(:string) { '7 + 7' }
      let(:result) { '14' }

      it "must parse the string and calculate the result" do
        expr = subject.parse(string)

        expect(expr).to be_kind_of(described_class)
        expect(expr.string).to eq(string)
        expect(expr.result).to eq(result)
      end
    end

    context "when given 'X-Z'" do
      let(:string) { '7-1' }
      let(:result) { '6'   }

      it "must parse the string and calculate the result" do
        expr = subject.parse(string)

        expect(expr).to be_kind_of(described_class)
        expect(expr.string).to eq(string)
        expect(expr.result).to eq(result)
      end
    end

    context "when given 'X - Z'" do
      let(:string) { '7 - 1' }
      let(:result) { '6'     }

      it "must parse the string and calculate the result" do
        expr = subject.parse(string)

        expect(expr).to be_kind_of(described_class)
        expect(expr.string).to eq(string)
        expect(expr.result).to eq(result)
      end
    end
  end

  describe "#to_s" do
    it "must return #string" do
      expect(subject.to_s).to eq(string)
    end
  end
end
