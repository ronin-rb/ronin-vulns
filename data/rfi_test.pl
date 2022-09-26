print <<'EOS';
<style type="text/css">
#rfi-security-alert {
  position: relative;
  margin: 25vh 25vw 25vh 25vw;
  padding: 5em;
  color: black;
  background-color: white;
  border: 4em solid red;
  z-index: 10000;
}
#rfi-security-alert p {
  text-align: center;
  font-weight: bold;
  font-size: 4em;
}
</style>
EOS

my $reversed_security_alert = "!detceteD )IFR( noisulcnI eliF etomeR :trelA ytiruceS";
my $security_alert = reverse($reversed_security_alert);

print "<div id=\"rfi-security-alert\">", "\n";
print "  <p>", $security_alert, "</p>\n";
print "</div>", "\n";
