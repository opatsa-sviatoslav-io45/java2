package ua.kpi.comsys.collections;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Аналізатор лог-файлів веб-сервера у форматі Common Log Format (CLF).
 *
 * <p>Приклад рядка, що вважається коректним:
 * {@code 192.168.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326}.
 * Рядки, що не відповідають формату, а також елементи, які не є рядками,
 * мовчки пропускаються.
 *
 * @author Sviatoslav Opatsa
 */
public class LogAnalyzer {

    /**
     * Шаблон одного рядка CLF. Іменована група {@code ip} містить IP-адресу клієнта.
     *
     * <p>Структура: {@code ip ident user [час] "запит" статус розмір},
     * де розмір може бути числом або символом {@code -}.
     */
    private static final Pattern CLF = Pattern.compile(
        "^(?<ip>\\S+) \\S+ \\S+ \\[[^\\]]+\\] \"[^\"]*\" \\d{3} (?:\\d+|-)$"
    );

    /**
     * Підраховує кількість коректних запитів для кожної IP-адреси.
     *
     * @param logLines список рядків логу (сирий тип дозволяє передати змішаний
     *                 вміст; елементи, що не є {@link String}, ігноруються)
     * @return відображення «IP-адреса → кількість запитів»
     * @throws IllegalArgumentException якщо {@code logLines} дорівнює {@code null}
     */
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

    /**
     * Повертає множину унікальних IP-адрес з коректних рядків логу.
     *
     * @param logLines список рядків логу, не може бути {@code null}
     * @return нова змінювана множина унікальних IP-адрес (порожня, якщо
     *         коректних рядків немає)
     * @throws IllegalArgumentException якщо {@code logLines} дорівнює {@code null}
     */
    public Set getUniqueIps(List logLines) {
        return new HashSet<>(countIps(logLines).keySet());
    }

    /**
     * Повертає {@code topN} найактивніших IP-адрес.
     *
     * <p>Порядок: за спаданням кількості запитів; за однакової кількості
     * адреси впорядковуються за алфавітом, тому результат детермінований.
     * Якщо унікальних адрес менше за {@code topN}, повертаються всі.
     *
     * @param logLines список рядків логу, не може бути {@code null}
     * @param topN     максимальна кількість адрес у результаті, не менше 0
     * @return список IP-адрес від найактивнішої до найменш активної
     * @throws IllegalArgumentException якщо {@code topN} від'ємне або
     *                                  {@code logLines} дорівнює {@code null}
     */
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