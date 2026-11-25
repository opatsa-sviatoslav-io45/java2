package ua.kpi.comsys.collections;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class LogAnalyzer {
    private static final Pattern CLF = Pattern.compile(
        "^(?<ip>\\S+) \\S+ \\S+ \\[[^\\]]+\\] \"[^\"]*\" \\d{3} (?:\\d+|-)$"
    );

    @SuppressWarnings("unchecked")
    private Map<String, Long> countIps(List logLines) {
        if (logLines == null) throw new IllegalArgumentException("logLines cannot be null");

        Map<String, Long> counts = new HashMap<>();
        for (Object o : (List<Object>) logLines) {
            if (!(o instanceof String)) continue;
            Matcher m = CLF.matcher((String) o);
            if (!m.matches()) continue;
            counts.merge(m.group("ip"), 1L, Long::sum);
        }
        return counts;
    }

    public Set getUniqueIps(List logLines) {
        return new HashSet<>(countIps(logLines).keySet());
    }

    public List getTopIps(List logLines, int topN) {
        if (topN < 0) throw new IllegalArgumentException("topN cannot be negative");

        return countIps(logLines).entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed()
                .thenComparing(Map.Entry.<String, Long>comparingByKey()))
            .limit(topN)
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());
    }
}