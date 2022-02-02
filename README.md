
# CSV-Compare - How To Use

CSV-Compare is a tool for comparing vulnerability scans as reported
in CSV files outputted by mergebase and OWASP-Dependency-Check tools.

Simply provide the two \*.csv files you wish to compare as input.

Vulnerabilities are catagorized based on whether they appeared
in "both" result sets, MergeBase-Only, or Dependency-Check-Only.

~~~~
$ java -jar csv-compare-2022.02.02.jar dependency-check-report.csv  mergebase.csv 

both,mergebase_only,dependency_check_only
CVE-2016-5725,,CWE-502: DESERIALIZATION OF UNTRUSTED DATA
CVE-2021-44228,,
CVE-2021-44832,,
CVE-2021-45046,,
CVE-2021-45105,,
~~~~
