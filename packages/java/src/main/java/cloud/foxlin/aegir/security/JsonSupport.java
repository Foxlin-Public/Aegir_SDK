package cloud.foxlin.aegir.security;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

final class JsonSupport
{
    private JsonSupport()
    {
    }

    static Object parse(String input)
    {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        if (engine == null)
        {
            return new Parser(input).parseValue();
        }

        try
        {
            return engine.eval("Java.asJSONCompatible(" + input + ")");
        }
        catch (ScriptException ex)
        {
            throw new IllegalArgumentException("Unable to parse JSON payload.", ex);
        }
    }

    static String stringify(Object value)
    {
        if (value == null)
        {
            return "null";
        }

        if (value instanceof String)
        {
            return "\"" + ((String) value)
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
        }

        if (value instanceof Number || value instanceof Boolean)
        {
            return value.toString();
        }

        if (value instanceof Map)
        {
            StringBuilder builder = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet())
            {
                if (!first)
                {
                    builder.append(',');
                }

                first = false;
                builder.append(stringify(entry.getKey().toString()));
                builder.append(':');
                builder.append(stringify(entry.getValue()));
            }

            return builder.append('}').toString();
        }

        if (value instanceof List)
        {
            StringBuilder builder = new StringBuilder("[");
            boolean first = true;
            for (Object item : (List<?>) value)
            {
                if (!first)
                {
                    builder.append(',');
                }

                first = false;
                builder.append(stringify(item));
            }

            return builder.append(']').toString();
        }

        throw new IllegalArgumentException("Unsupported JSON value type: " + value.getClass().getName());
    }

    private static final class Parser
    {
        private final String input;
        private int index;

        Parser(String input)
        {
            this.input = input;
        }

        Object parseValue()
        {
            skipWhitespace();
            char current = input.charAt(index);

            switch (current)
            {
                case '{':
                    return parseObject();
                case '[':
                    return parseArray();
                case '"':
                    return parseString();
                case 't':
                    index += 4;
                    return Boolean.TRUE;
                case 'f':
                    index += 5;
                    return Boolean.FALSE;
                case 'n':
                    index += 4;
                    return null;
                default:
                    return parseNumber();
            }
        }

        private Map<String, Object> parseObject()
        {
            Map<String, Object> payload = new LinkedHashMap<>();
            index++;
            skipWhitespace();
            if (input.charAt(index) == '}')
            {
                index++;
                return payload;
            }

            while (true)
            {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                index++;
                Object value = parseValue();
                payload.put(key, value);
                skipWhitespace();
                char separator = input.charAt(index++);
                if (separator == '}')
                {
                    return payload;
                }
            }
        }

        private List<Object> parseArray()
        {
            List<Object> items = new ArrayList<>();
            index++;
            skipWhitespace();
            if (input.charAt(index) == ']')
            {
                index++;
                return items;
            }

            while (true)
            {
                skipWhitespace();
                items.add(parseValue());
                skipWhitespace();
                char separator = input.charAt(index++);
                if (separator == ']')
                {
                    return items;
                }
            }
        }

        private String parseString()
        {
            StringBuilder builder = new StringBuilder();
            index++;
            while (true)
            {
                char current = input.charAt(index++);
                if (current == '"')
                {
                    return builder.toString();
                }

                if (current == '\\')
                {
                    char escaped = input.charAt(index++);
                    switch (escaped)
                    {
                        case '"':
                        case '\\':
                        case '/':
                            builder.append(escaped);
                            break;
                        case 'b':
                            builder.append('\b');
                            break;
                        case 'f':
                            builder.append('\f');
                            break;
                        case 'n':
                            builder.append('\n');
                            break;
                        case 'r':
                            builder.append('\r');
                            break;
                        case 't':
                            builder.append('\t');
                            break;
                        case 'u':
                            builder.append((char) Integer.parseInt(input.substring(index, index + 4), 16));
                            index += 4;
                            break;
                        default:
                            throw new IllegalArgumentException("Unsupported escape sequence: \\" + escaped);
                    }
                }
                else
                {
                    builder.append(current);
                }
            }
        }

        private Number parseNumber()
        {
            int start = index;
            while (index < input.length())
            {
                char current = input.charAt(index);
                if ("-+0123456789.eE".indexOf(current) < 0)
                {
                    break;
                }
                index++;
            }

            String token = input.substring(start, index);
            if (token.contains(".") || token.contains("e") || token.contains("E"))
            {
                return Double.parseDouble(token);
            }

            return Long.parseLong(token);
        }

        private void skipWhitespace()
        {
            while (index < input.length())
            {
                char current = input.charAt(index);
                if (!Character.isWhitespace(current))
                {
                    return;
                }
                index++;
            }
        }
    }
}
