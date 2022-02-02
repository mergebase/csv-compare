package com.mergebase.csv;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;

import java.io.File;
import java.io.IOException;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

public class CompareMain {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: java -jar csv-compare.jar file1.csv file2.csv");
            System.exit(1);
        }

        File f1 = new File(args[0]);
        File f2 = new File(args[1]);
        if (!f1.canRead() || !f1.isFile() || f1.length() <= 0) {
            System.out.println("Invalid file (empty, or cannot-read):  " + args[0]);
            System.exit(1);
        }
        if (!f2.canRead() || !f2.isFile() || f2.length() <= 0) {
            System.out.println("Invalid file (empty, or cannot-read):  " + args[1]);
            System.exit(1);
        }

        String s1 = Bytes.fileToString(f1);
        String s2 = Bytes.fileToString(f2);

        boolean[] mergebaseIsSet1 = new boolean[1];
        boolean[] mergebaseIsSet2 = new boolean[1];
        Set<String> cves1 = extractCves(s1, mergebaseIsSet1);
        Set<String> cves2 = extractCves(s2, mergebaseIsSet2);
        if (mergebaseIsSet1[0] && mergebaseIsSet2[0]) {
            System.out.println("Error - Cannot Compare - Both CSV files are MergeBase format! !?!? ");
            System.exit(1);
        }
        if (!mergebaseIsSet1[0] && !mergebaseIsSet2[0]) {
            System.out.println("Error - Cannot Compare - Neither CSV files are MergeBase format! !?!? ");
            System.exit(1);
        }

        Set<String> both = new TreeSet<>(cves1);
        both.retainAll(cves2);
        cves1.removeAll(both);
        cves2.removeAll(both);


        final CSVFormat.Builder builder = CSVFormat.EXCEL.builder();
        builder.setHeader("both", "mergebase_only", "dependency_check_only");
        final CSVFormat csvFormat = builder.build();
        final CSVPrinter printer = new CSVPrinter(System.out, csvFormat);
        Iterator<String> it1 = both.iterator();
        Iterator<String> it2 = mergebaseIsSet1[0] ? cves1.iterator() : cves2.iterator();
        Iterator<String> it3 = mergebaseIsSet1[0] ? cves2.iterator() : cves1.iterator();
        while (it1.hasNext() || it2.hasNext() || it3.hasNext()) {
            String vuln1 = it1.hasNext() ? it1.next() : "";
            String vuln2 = it2.hasNext() ? it2.next() : "";
            String vuln3 = it3.hasNext() ? it3.next() : "";
            printer.printRecord(vuln1, vuln2, vuln3);
        }

    }

    private static Set<String> extractCves(String csv, boolean[] isMergeBase) throws IOException {
        Set<String> set = new TreeSet<>();

        CSVParser parser = CSVParser.parse(csv, CSVFormat.DEFAULT.withFirstRecordAsHeader());
        Map<String, Integer> headerMap = parser.getHeaderMap();
        String[] headers = new String[headerMap.size()];
        for (Map.Entry<String, Integer> entry : headerMap.entrySet()) {
            String name = entry.getKey();
            Integer val = entry.getValue();
            headers[val] = name;
        }

        for (CSVRecord r : parser) {
            Map<String, String> data = new TreeMap<>();
            for (String key : headers) {
                String val = r.get(key);
                data.put(key, val);
            }

            String mergeBaseCve = data.get("vuln");
            String depCheckCve = data.get("CVE");
            mergeBaseCve = mergeBaseCve != null ? mergeBaseCve.trim().toUpperCase(Locale.ROOT) : "";
            depCheckCve = depCheckCve != null ? depCheckCve.trim().toUpperCase(Locale.ROOT) : "";
            if (!"".equals(mergeBaseCve)) {
                set.add(mergeBaseCve);
                isMergeBase[0] = true;
            }
            if (!"".equals(depCheckCve)) {
                set.add(depCheckCve);
            }
        }
        return set;
    }
}