#!/bin/bash
cat pglines | while read -a arr
do
echo Writing ${arr[0]}
if [[ $((${arr[2]}-${arr[1]}-1)) -eq 0 ]]
then
touch ${arr[0]}.tsv
else
time tail -n +$((${arr[1]}+1)) ~/pwhois.pgdump | \
head -n $((${arr[2]}-${arr[1]}-1)) > ${arr[0]}.tsv
fi
done
