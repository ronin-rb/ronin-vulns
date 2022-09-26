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
@{
    string reversed_security_alert = "!detceteD )IFR( noisulcnI eliF etomeR :trelA ytiruceS";
    char[] security_alert_chars = reversed_security_alert.ToCharArray();
    Array.Reverse(security_alert_chars);
    string security_alert = new string(security_alert_chars);
}
<div id="rfi-security-alert">
  <p>@security_alert</p>
</div>
