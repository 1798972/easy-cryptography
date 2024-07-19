package cn.yang37.utils;

import org.slf4j.MDC;

import java.util.UUID;

/**
 * @description:
 * @class: TraceUtils
 * @author: yang37z@qq.com
 * @date: 2024/7/20 1:49
 * @version: 1.0
 */
public class TraceUtils {

    /**
     * log-traceId
     */
    public static final String TRACE_ID = "traceId";

    /**
     * log-preMsg
     */
    public static final String PRE_MSG = "preMsg";

    /**
     * 自动traceId
     */
    public static void start() {
        MDC.put(TRACE_ID, generateTraceId());
    }

    /**
     * 自动traceId + 传入preMsg
     */
    public static void start(String preMsg) {
        MDC.put(PRE_MSG, preMsg);
        start();
    }

    /**
     * 传入traceId
     */
    public static void start4TraceId(String traceId) {
        MDC.put(TRACE_ID, traceId);
    }

    /**
     * 传入traceId + 传入preMsg
     */
    public static void start4TraceId(String traceId, String preMsg) {
        MDC.put(PRE_MSG, preMsg);
        start4TraceId(traceId);
    }

    private static String generateTraceId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

}