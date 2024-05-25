#!awk -f
/Total possibly gain / { total += $4 }
/Size of moveable sections/ { smove += $5 }
END { print total; print smove }