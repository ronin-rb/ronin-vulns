<?php
echo <<<EOS
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
EOS . PHP_EOL;

echo "<div id=\"rfi-security-alert\">" . PHP_EOL;
echo "  <p>" . strrev("!detceteD )IFR( noisulcnI eliF etomeR :trelA ytiruceS") . "</p>" . PHP_EOL;
echo "</div>" . PHP_EOL;
?>
