package ua.kpi.comsys.collections;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class LogAnalyzerTest {

    private LogAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new LogAnalyzer();
    }

    private static String line(String ip) {
        return ip + " - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326";
    }

    private static String lineWithDash(String ip) {
        return ip + " - - [10/Oct/2000:13:55:36 -0700] \"GET /index.html HTTP/1.1\" 304 -";
    }
    
    @Test
    @DisplayName("getUniqueIps: null throws IllegalArgumentException")
    void uniqueIps_nullThrows() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.getUniqueIps(null));
    }

    @Test
    @DisplayName("getUniqueIps: empty list returns empty set")
    void uniqueIps_empty() {
        Set result = analyzer.getUniqueIps(new ArrayList<String>());
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("getUniqueIps: duplicates are collapsed")
    void uniqueIps_deduplicates() {
        List<String> logs = Arrays.asList(
            line("192.168.0.1"),
            line("10.0.0.5"),
            line("192.168.0.1"),
            line("192.168.0.1"),
            line("10.0.0.5")
        );

        Set result = analyzer.getUniqueIps(logs);

        assertEquals(2, result.size());
        assertTrue(result.contains("192.168.0.1"));
        assertTrue(result.contains("10.0.0.5"));
    }

    @Test
    @DisplayName("getUniqueIps: returns IP strings, not ip=count pairs")
    void uniqueIps_returnsIpStrings() {
        Set result = analyzer.getUniqueIps(Collections.singletonList(line("1.2.3.4")));

        Object only = result.iterator().next();
        assertTrue(only instanceof String);
        assertEquals("1.2.3.4", only);
    }

    @Test
    @DisplayName("getUniqueIps: malformed lines are ignored")
    void uniqueIps_ignoresMalformed() {
        List<String> logs = Arrays.asList(
            "this is not a log line",
            "",
            "127.0.0.1 - - [bad date",
            line("8.8.8.8"),
            "127.0.0.1 GET /index.html",
            "   "
        );

        Set result = analyzer.getUniqueIps(logs);

        assertEquals(1, result.size());
        assertTrue(result.contains("8.8.8.8"));
    }

    @Test
    @DisplayName("getUniqueIps: response size '-' is supported")
    void uniqueIps_dashSize() {
        Set result = analyzer.getUniqueIps(Collections.singletonList(lineWithDash("4.4.4.4")));
        assertEquals(Set.of("4.4.4.4"), result);
    }

    @Test
    @DisplayName("getUniqueIps: IPv6 and hostnames are supported")
    void uniqueIps_ipv6AndHostname() {
        List<String> logs = Arrays.asList(
            line("::1"),
            line("2001:db8::ff00:42:8329"),
            line("example.com")
        );

        assertEquals(3, analyzer.getUniqueIps(logs).size());
    }

    @Test
    @DisplayName("getUniqueIps: non-string elements are skipped")
    void uniqueIps_nonStringElementsSkipped() {
        List logs = new ArrayList();
        logs.add(line("5.5.5.5"));
        logs.add(42);
        logs.add(null);

        Set result = analyzer.getUniqueIps(logs);

        assertEquals(Set.of("5.5.5.5"), result);
    }

    @Test
    @DisplayName("getUniqueIps: input list is not modified")
    void uniqueIps_doesNotMutateInput() {
        List<String> logs = new ArrayList<>(Arrays.asList(line("1.1.1.1"), "garbage"));
        List<String> copy = new ArrayList<>(logs);

        analyzer.getUniqueIps(logs);

        assertEquals(copy, logs);
    }


    @Test
    @DisplayName("getTopIps: null throws IllegalArgumentException")
    void topIps_nullThrows() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.getTopIps(null, 3));
    }

    @Test
    @DisplayName("getTopIps: negative topN throws IllegalArgumentException")
    void topIps_negativeThrows() {
        assertThrows(IllegalArgumentException.class,
            () -> analyzer.getTopIps(new ArrayList<String>(), -1));
    }

    @Test
    @DisplayName("getTopIps: empty list returns empty result")
    void topIps_empty() {
        List result = analyzer.getTopIps(new ArrayList<String>(), 5);
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("getTopIps: topN = 0 returns empty result")
    void topIps_zero() {
        List<String> logs = Arrays.asList(line("1.1.1.1"), line("2.2.2.2"));
        assertTrue(analyzer.getTopIps(logs, 0).isEmpty());
    }

    @Test
    @DisplayName("getTopIps: sorted by request count, descending")
    void topIps_sortedByCountDesc() {
        List<String> logs = Arrays.asList(
            line("1.1.1.1"),
            line("2.2.2.2"), line("2.2.2.2"), line("2.2.2.2"),
            line("3.3.3.3"), line("3.3.3.3")
        );

        List result = analyzer.getTopIps(logs, 3);

        assertEquals(Arrays.asList("2.2.2.2", "3.3.3.3", "1.1.1.1"), result);
    }

    @Test
    @DisplayName("getTopIps: result is limited to topN")
    void topIps_limitsToTopN() {
        List<String> logs = Arrays.asList(
            line("1.1.1.1"),
            line("2.2.2.2"), line("2.2.2.2"), line("2.2.2.2"),
            line("3.3.3.3"), line("3.3.3.3")
        );

        List result = analyzer.getTopIps(logs, 2);

        assertEquals(Arrays.asList("2.2.2.2", "3.3.3.3"), result);
    }

    @Test
    @DisplayName("getTopIps: topN larger than unique count returns all IPs")
    void topIps_topNLargerThanUnique() {
        List<String> logs = Arrays.asList(line("1.1.1.1"), line("2.2.2.2"), line("2.2.2.2"));

        List result = analyzer.getTopIps(logs, 100);

        assertEquals(Arrays.asList("2.2.2.2", "1.1.1.1"), result);
    }

    @Test
    @DisplayName("getTopIps: ties are broken by IP (deterministic order)")
    void topIps_tieBreakByIp() {
        List<String> logs = Arrays.asList(
            line("9.9.9.9"),
            line("1.1.1.1"),
            line("5.5.5.5")
        );

        List result = analyzer.getTopIps(logs, 3);

        assertEquals(Arrays.asList("1.1.1.1", "5.5.5.5", "9.9.9.9"), result);
    }

    @Test
    @DisplayName("getTopIps: malformed lines do not affect counts")
    void topIps_ignoresMalformed() {
        List<String> logs = Arrays.asList(
            "garbage",
            line("7.7.7.7"),
            "7.7.7.7 broken line",
            "",
            line("8.8.8.8"), line("8.8.8.8")
        );

        List result = analyzer.getTopIps(logs, 5);

        assertEquals(Arrays.asList("8.8.8.8", "7.7.7.7"), result);
    }

    @Test
    @DisplayName("getTopIps: result is a List")
    void topIps_returnsList() {
        Object result = analyzer.getTopIps(Collections.singletonList(line("1.1.1.1")), 1);
        assertTrue(result instanceof List);
    }
}