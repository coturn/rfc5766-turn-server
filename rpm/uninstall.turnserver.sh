#!/bin/sh

for i in `rpm -q -a | grep turnserver-utils-2`
do
  echo $i
  rpm -e $i
done

for i in `rpm -q -a | grep turnserver-client-libs-2`
do
  echo $i
  rpm -e $i
done

for i in `rpm -q -a | grep turnserver.*-2`
do
  echo $i
  rpm -e $i
done
