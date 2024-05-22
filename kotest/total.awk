#!awk -f
$0 ~ /Total possibly gain / { total += $4 }
END { print total }