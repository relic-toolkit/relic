cat script.sed
/PATTERN/ {
  r copyright.txt
  d
}

