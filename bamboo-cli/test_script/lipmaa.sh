#!/bin/bash
LIPMAA=100000

while [ $LIPMAA -gt 0 ]; do
  echo $LIPMAA
  let LIPMAA=$( ./bamboo-cli lipmaa $LIPMAA )
done
