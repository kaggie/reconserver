#!/bin/bash
echo "Dummy recon script"
echo "Input path: $1"
echo "Output path: $3"
# Create a dummy output file
echo "This is a dummy output file" > "$3/dummy_output.txt"
exit 0
