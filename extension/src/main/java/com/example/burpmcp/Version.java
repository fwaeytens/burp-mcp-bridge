package com.example.burpmcp;

/**
 * Version information for Burp MCP Bridge.
 * This class provides version tracking and release information.
 */
public class Version {
    
    // Version components
    public static final String VERSION = "2.3.1";
    public static final String BUILD_DATE = "2026-04-04";
    public static final String RELEASE_NAME = "Montoya API 2026.2";

    // Feature tracking
    public static final int TOOL_COUNT = 22; // Total number of registered tools
    public static final boolean ASYNC_ENABLED = true;
    public static final boolean CONFIG_ENABLED = true;

    // Compatibility
    public static final String MIN_BURP_VERSION = "2026.2";
    public static final String MIN_JAVA_VERSION = "17";
    public static final String MONTOYA_API_VERSION = "2026.2";
    
    /**
     * Get complete version information.
     */
    public static String getVersionInfo() {
        StringBuilder info = new StringBuilder();
        info.append("Burp MCP Bridge v").append(VERSION).append("\n");
        info.append("Release: ").append(RELEASE_NAME).append("\n");
        info.append("Build Date: ").append(BUILD_DATE).append("\n");
        info.append("Tools: ").append(TOOL_COUNT).append(" available\n");
        info.append("Features: ");
        
        if (ASYNC_ENABLED) info.append("Async Processing, ");
        if (CONFIG_ENABLED) info.append("Configuration Management, ");
        info.append("URL Encoding, Error Handling\n");
        
        info.append("Compatibility: Burp ").append(MIN_BURP_VERSION)
            .append("+, Java ").append(MIN_JAVA_VERSION)
            .append("+, Montoya API ").append(MONTOYA_API_VERSION);
        
        return info.toString();
    }
    
    /**
     * Get short version string.
     */
    public static String getShortVersion() {
        return "v" + VERSION;
    }
    
    /**
     * Get detailed changelog for this version.
     */
    public static String getChangelog() {
        return "## Version 2.3.1 - Scanner insertion points, collaborator logging (2026-04-04)\n\n" +
               "### 🎯 Scanner Improvements\n" +
               "- ✅ **insertionPointParams**: Scan specific parameters by name (auto-resolves byte offsets)\n" +
               "- ✅ **insertionPointValues**: Scan specific values by string match\n" +
               "- ✅ **getAsArray**: Handles LLMs sending arrays as JSON strings\n" +
               "\n" +
               "### 🔍 Collaborator Logging\n" +
               "- ✅ **Client creation**: Logged to Extensions > Output on first use\n" +
               "- ✅ **Payload generation**: Logged with payload string and ID\n" +
               "- ✅ **Interactions**: Logged with type, client IP, and timestamp\n" +
               "\n" +
               "## Version 2.3.0 - MCP SDK 1.29.0 (2026-04-02)\n\n" +
               "### 🔄 MCP SDK Upgrade\n" +
               "- ✅ **MCP SDK**: Upgraded from 0.6.0 to 1.29.0\n" +
               "- ✅ **StreamableHTTP**: New transport available for modern MCP clients\n" +
               "\n" +
               "### 🤖 Agent Discovery Improvements\n" +
               "- ✅ **SERVER INSTRUCTIONS**: initialize response includes usage rules for all MCP clients\n" +
               "- ✅ **SEARCH HINTS**: All 22 tools have _meta/anthropic/searchHint for ToolSearch discovery\n" +
               "- ✅ **ALWAYS LOAD**: burp_help and burp_custom_http marked as alwaysLoad (no deferral)\n" +
               "- ✅ **TITLE IN ANNOTATIONS**: title in both top-level and annotations for all clients\n" +
               "\n" +
               "### 🔧 Bridge Improvements\n" +
               "- ✅ **RESULT TRUNCATION**: Prevents silent data loss at 95K char limit\n" +
               "- ✅ **STRUCTURED CONTENT**: Drops structuredContent before text truncation\n" +
               "\n" +
               "## Version 2.0.5 - CustomHttpTool Fixes (2026-01-27)\n\n" +
               "### 🐛 Bug Fixes\n" +
               "- ✅ **SCHEME OVERRIDE**: Explicit scheme takes precedence over port-based detection\n" +
               "- ✅ **ABSOLUTE-FORM URL**: Port/host extraction and auto Host header insertion when needed\n" +
               "- ✅ **SEND_PARALLEL STABILITY**: Guarded legacy Montoya API paths\n" +
               "- ✅ **IPv6 PARSING**: Proper handling for IPv6 literals in protocol analysis\n" +
               "\n" +
               "## Version 2.0.4 - Code Cleanup (2026-01-27)\n\n" +
               "### 🧹 Maintenance\n" +
               "- ✅ **CustomHttpTool cleanup**: Removed unused code and parameters\n" +
               "\n" +
               "## Version 2.0.3 - Shell Execution + HTTPS Default (2025-12-15)\n\n" +
               "### 🔒 Security & Platform\n" +
               "- ✅ **ShellUtils support**: shell_execute and shell_execute_dangerous\n" +
               "- ✅ **HTTPS default**: burp_custom_http now defaults to HTTPS\n" +
               "\n" +
               "## Version 1.8.2 - Response Anomaly Detection with RankingUtils (2025-10-21)\n\n" +
               "### 🎯 NEW: AI-Powered Anomaly Detection\n" +
               "- ✅ **NEW FEATURE**: rank_anomalies action in burp_response_analyzer tool\n" +
               "- ✅ **MONTOYA API 2025.10**: Upgraded to latest API with RankingUtils support\n" +
               "- ✅ **ANOMALY ALGORITHM**: Uses Burp's built-in anomaly detection to rank responses\n" +
               "- ✅ **SMART PRIORITIZATION**: Automatically identifies most interesting/unusual responses\n" +
               "- ✅ **SECURITY FOCUS**: Highlights potential vulnerabilities and unexpected behavior\n" +
               "- ✅ **ACTIONABLE INSIGHTS**: Color-coded ranking (🔴 Very High, 🟠 High, 🟡 Medium, 🟢 Low, ⚪ Very Low)\n" +
               "\n" +
               "### 📊 RankingUtils Features\n" +
               "- **Automated Analysis**: Analyzes up to 100 proxy history responses (configurable)\n" +
               "- **Top N Results**: Returns top 10 most anomalous responses by default\n" +
               "- **Distribution Stats**: Shows anomaly level distribution across all responses\n" +
               "- **Detailed Output**: URL, method, status, size, content-type for each ranked item\n" +
               "- **Security Guidance**: Explains what high-ranked anomalies typically indicate\n" +
               "\n" +
               "### 🔧 Technical Updates\n" +
               "- **API Version**: Upgraded from Montoya API 2025.8 → 2025.10\n" +
               "- **New Imports**: RankingUtils, RankingAlgorithm, RankedHttpRequestResponse\n" +
               "- **Min Burp Version**: Now requires Burp Suite 2025.10+\n" +
               "- **Backward Compatible**: All existing ResponseAnalysisTool actions unchanged\n" +
               "\n" +
               "### 💡 Use Cases\n" +
               "- Quickly identify error responses in large proxy histories\n" +
               "- Find authorization bypass candidates (different admin vs user responses)\n" +
               "- Detect unexpected application states or behaviors\n" +
               "- Prioritize security testing on most anomalous endpoints\n" +
               "- Reduce manual analysis time by focusing on outliers\n" +
               "\n" +
               "## Version 1.8.1 - Enhanced Annotation Tool Documentation (2025-09-28)\n\n" +
               "### 📚 Documentation & Testing Enhancements\n" +
               "- ✅ **COMPREHENSIVE DOCS**: Created detailed ANNOTATE_TOOL_DOCUMENTATION.md with all 16 actions\n" +
               "- ✅ **FULL EXAMPLES**: Added practical examples for every annotation action\n" +
               "- ✅ **TEST SUITE**: Multiple test scripts for complete AnnotateTool validation\n" +
               "- ✅ **INTERNAL DB EXPLAINED**: Documented the HashMap-based storage for non-API components\n" +
               "- ✅ **WORKFLOW EXAMPLES**: Added security assessment and collaborative testing workflows\n" +
               "- ✅ **BEST PRACTICES**: Color coding guidelines and annotation strategies\n" +
               "\n" +
               "### 🔧 Bug Fixes\n" +
               "- ✅ **HANDLER REGISTRATION**: Added proper Registration tracking for auto-annotation\n" +
               "- ✅ **DEREGISTRATION**: Fixed memory leak from accumulating proxy handlers\n" +
               "- ✅ **IMPORT LIBRARY**: Added missing Registration import\n" +
               "\n" +
               "### 📊 Technical Details\n" +
               "- **Documentation**: 500+ lines of comprehensive tool documentation\n" +
               "- **Test Coverage**: 20+ test scenarios covering all actions\n" +
               "- **Code Improvements**: Proper handler lifecycle management\n" +
               "- **No Breaking Changes**: Fully backward compatible with v1.8.0\n" +
               "\n" +
               "## Version 1.8.0 - Self-Documenting AI Discovery System (2025-08-29)\n\n" +
               "### 🤖 NEW: Complete Self-Documentation System for AI Agents\n" +
               "- ✅ **4 NEW DOCUMENTATION TOOLS**: Enable complete AI self-discovery without external files\n" +
               "- ✅ **get_documentation**: ALWAYS CALL FIRST! Complete tool documentation for all 33 tools\n" +
               "- ✅ **discover_tools**: Find tools by capability, input type, or use case\n" +
               "- ✅ **get_workflow**: Step-by-step workflows for common security testing tasks\n" +
               "- ✅ **get_tool_help**: Detailed help for any specific tool with examples\n" +
               "- ✅ **TOOLS APPEAR FIRST**: Documentation tools prioritized in tool list for AI discovery\n" +
               "- ✅ **100% IN-MEMORY**: All documentation stored internally - no external files needed\n" +
               "- ✅ **AI-OPTIMIZED**: Designed for LLM agents to discover and learn tool usage autonomously\n" +
               "\n" +
               "### 📊 Documentation System Features\n" +
               "- **Tools Documented**: All 33 tools (29 security + 4 documentation) with complete parameters and examples\n" +
               "- **Workflow Patterns**: 7 pre-defined workflows (OWASP Top 10, API testing, etc.)\n" +
               "- **Tool Discovery**: Semantic search by capability, categorization, and tagging\n" +
               "- **Self-Contained**: AI agents can learn everything through tool calls alone\n" +
               "- **Total Tools**: 33 (29 existing + 4 documentation tools)\n" +
               "\n" +
               "## Version 1.7.47 - Enhanced Response Analysis & Utilities with Full Montoya API (2025-08-29)\n\n" +
               "### 🔍 Response Analyzer Tool Major Enhancement\n" +
               "- ✅ **ALL ATTRIBUTE TYPES**: Now analyzes all 30+ AttributeType variations for comprehensive insights\n" +
               "- ✅ **PATTERN ANALYSIS**: New regex pattern search using ByteUtils for finding sensitive data\n" +
               "- ✅ **CATEGORIZED RESULTS**: Attributes grouped by Headers, Content, Structure, Forms, Links, Metadata\n" +
               "- ✅ **ENHANCED INSIGHTS**: Detailed security recommendations based on variant attributes\n" +
               "\n" +
               "### 🛠️ Utilities Tool Complete Enhancement\n" +
               "- ✅ **JSON PATH OPERATIONS**: Full JsonUtils support - read/add/update/remove with path expressions\n" +
               "- ✅ **NUMBER CONVERSIONS**: Complete NumberUtils - binary/octal/decimal/hex conversions\n" +
               "- ✅ **BYTE SEARCH**: ByteUtils pattern matching for binary data analysis\n" +
               "- ✅ **JSON VALIDATION**: Check and validate JSON structure with detailed feedback\n" +
               "- ✅ **100% MONTOYA COVERAGE**: All available utility APIs now exposed\n" +
               "\n" +
               "## Version 1.7.46 - WebSocket Tool Improvements & Documentation (2025-08-29)\n\n" +
               "### 🐛 Bug Fixes & Improvements\n" +
               "- ✅ **WEBSOCKET CREATION FIX**: Fixed null pointer exception in WebSocket creation with custom upgrade requests\n" +
               "- ✅ **GLOBAL INTERCEPTOR**: Enhanced with WebSocket upgrade logging and clarified documentation\n" +
               "- ✅ **DOCUMENTATION**: Created comprehensive WebSocket Tools Guide for proper tool selection\n" +
               "- ✅ **TOOL DESCRIPTIONS**: Updated all WebSocket tools with clearer usage instructions\n\n" +
               "## Version 1.7.45 - Full Binary WebSocket Interception Support (2025-08-29)\n\n" +
               "### 🔌 WebSocketInterceptorTool - 100% Feature Complete\n" +
               "- ✅ **BINARY MESSAGE INTERCEPTION**: Full support for intercepting binary WebSocket messages\n" +
               "- ✅ **BINARY MESSAGE MODIFICATION**: Modify binary payloads via Base64 encoding\n" +
               "- ✅ **BINARY MESSAGE FILTERING**: Apply regex filters to hex representation of binary data\n" +
               "- ✅ **COMPLETE PARITY**: Both text and binary messages now have identical capabilities\n" +
               "- ✅ **100% MONTOYA API COVERAGE**: All WebSocket proxy handler methods fully implemented\n\n" +
               "### 📊 Technical Details\n" +
               "- **New Features**: processBinaryMessageReceived/ToBeSent fully implemented\n" +
               "- **Binary Handling**: Base64 for modification, hex for filtering\n" +
               "- **API Methods**: BinaryMessageReceivedAction/ToBeSentAction with drop/modify/continue\n" +
               "- **Queue Display**: Shows binary messages with Base64 payload and size info\n\n" +
               "## Version 1.7.44 - Enhanced Logs Tool with 100% Montoya API Coverage (2025-08-29)\n\n" +
               "### 📝 LogsTool Complete Enhancement\n" +
               "- ✅ **100% MONTOYA COVERAGE**: All Logging interface methods now utilized\n" +
               "- ✅ **OBJECT LOGGING**: Support for logToOutput(Object) to log complex objects\n" +
               "- ✅ **EXCEPTION LOGGING**: Full exception support with logToError(Throwable) and logToError(String, Throwable)\n" +
               "- ✅ **ENHANCED PARAMETERS**: New object, exceptionMessage, and stackTrace parameters\n" +
               "- ✅ **BETTER ERROR HANDLING**: Tool itself uses enhanced exception logging\n" +
               "- ✅ **BACKWARD COMPATIBLE**: Existing functionality unchanged\n\n" +
               "### 📊 Technical Details\n" +
               "- **New Methods**: logToOutput(Object), logToError(Throwable), logToError(String, Throwable)\n" +
               "- **Enhanced Actions**: WRITE_LOG now supports objects and exceptions\n" +
               "- **API Coverage**: 11 out of 11 Logging API methods now exposed (was 8/11)\n" +
               "- **Use Cases**: Better debugging with stack traces, JSON object logging\n\n" +
               "## Version 1.7.43 - Complete HTTP Tool with 100% Montoya API Coverage (2025-08-29)\n\n" +
               "### 🚀 CustomHttpTool Complete Enhancement\n" +
               "- ✅ **100% MONTOYA COVERAGE**: All HTTP interface methods now utilized\n" +
               "- ✅ **HTTP/2 IGNORE_ALPN**: Support for HTTP/2 without ALPN negotiation\n" +
               "- ✅ **ALL REDIRECTION MODES**: ALWAYS, NEVER, SAME_HOST, IN_SCOPE\n" +
               "- ✅ **SERVER NAME INDICATION**: Custom SNI for TLS connections\n" +
               "- ✅ **REQUEST TRANSFORMATIONS**: TOGGLE_METHOD transformation (GET↔POST)\n" +
               "- ✅ **PROTOCOL ANALYSIS**: Analyze HTTP vs HTTPS with detailed info\n" +
               "- ✅ **ENHANCED OPTIONS**: Complete RequestOptions API coverage\n\n" +
               "### 📊 Technical Details\n" +
               "- **New Actions**: TOGGLE_REQUEST_METHOD, ANALYZE_PROTOCOL\n" +
               "- **Enhanced Parameters**: redirection_mode, server_name_indicator, HTTP_2_IGNORE_ALPN\n" +
               "- **API Coverage**: 100% of Montoya HTTP interface now exposed\n" +
               "- **Backward Compatible**: Legacy follow_redirects parameter still supported\n\n" +
               "## Version 1.7.42 - Enhanced BambdaTool with Full Montoya API Compliance (2025-08-29)\n\n" +
               "### 🎭 BambdaTool Major Enhancement\n" +
               "- ✅ **PROPER YAML FORMAT**: Correctly formats Bambdas with id, name, function, location, source fields\n" +
               "- ✅ **MULTI-LOCATION SUPPORT**: Apply filters to PROXY_HTTP_HISTORY, PROXY_WS_HISTORY, SITEMAP, LOGGER\n" +
               "- ✅ **FULL ERROR HANDLING**: Uses BambdaImportResult.status() and importErrors() for detailed feedback\n" +
               "- ✅ **LOCATION-AWARE**: Provides location-specific tips and effects for better user guidance\n" +
               "- ✅ **CORRECTED SCRIPTS**: Fixed all pre-defined Bambda scripts with proper method calls\n" +
               "- ✅ **API LIMITATIONS DOCUMENTED**: Clear documentation of what Montoya API can and cannot do\n" +
               "- ✅ **100% MONTOYA COMPLIANCE**: Properly uses all available Bambda API methods\n\n" +
               "## Version 1.7.41 - Cleaned up Montoya API focus - removed non-API tools (2025-08-29)\n\n" +
               "### 🧹 Tool Cleanup\n" +
               "- **Removed Tools**: burp_sitemap_export and burp_enhanced_sitemap_export\n" +
               "- **Focus**: Maintaining 100% Montoya API utilization for all remaining tools\n" +
               "- **Tool Count**: Reduced from 32 to 29 tools to focus on core Montoya API functionality\n" +
               "- **Benefit**: Cleaner, more focused tool set aligned with Montoya API capabilities\n\n" +
               "## Version 1.7.40 - Enhanced SiteMapAnalysisTool with Full Montoya API (2025-08-29)\n\n" +
               "### 🗺️ SiteMapAnalysisTool Major Enhancement\n" +
               "- ✅ **RESPONSE VARIATIONS**: Uses ResponseVariationsAnalyzer to detect dynamic content\n" +
               "- ✅ **KEYWORD ANALYSIS**: Uses ResponseKeywordsAnalyzer for variant/invariant keywords\n" +
               "- ✅ **TIMING DATA**: Collects actual response times using TimingData API\n" +
               "- ✅ **DIRECT API METHODS**: Uses request().url(), response().statusCode(), response().mimeType()\n" +
               "- ✅ **ANNOTATIONS SUPPORT**: Detects and reports annotated entries\n" +
               "- ✅ **MARKERS DETECTION**: Identifies entries with request/response markers\n" +
               "- ✅ **ENHANCED PATTERNS**: More technology and sensitive data patterns\n" +
               "- ✅ **100% MONTOYA COVERAGE**: All available SiteMap analysis APIs utilized\n\n" +
               "### 📊 Technical Details\n" +
               "- **New Actions**: RESPONSE_VARIATIONS, KEYWORD_ANALYSIS with full Montoya API\n" +
               "- **Enhanced Actions**: RESPONSE_STATS now includes timing data, CONTENT_ANALYSIS uses markers\n" +
               "- **API Usage**: ResponseVariationsAnalyzer, ResponseKeywordsAnalyzer, TimingData, Annotations\n" +
               "- **Performance**: Direct API methods reduce overhead and improve accuracy\n" +
               "- **Insights**: Dynamic vs static content detection, keyword variance analysis\n\n" +
               "## Version 1.7.39 - Enhanced AnnotateTool with Complete Montoya API Integration (2025-08-29)\n\n" +
               "### 🎨 AnnotateTool Major Enhancement\n" +
               "- ✅ **REPEATER ANNOTATIONS**: Database-backed annotation storage for Repeater tabs\n" +
               "- ✅ **INTRUDER ANNOTATIONS**: Track and annotate Intruder attack results\n" +
               "- ✅ **SCANNER ANNOTATIONS**: Annotate scanner issues with custom notes\n" +
               "- ✅ **WEBSOCKET SUPPORT**: Full WebSocket message annotation via ProxyWebSocketMessage.annotations()\n" +
               "- ✅ **COLLABORATOR TRACKING**: Annotate Collaborator interactions\n" +
               "- ✅ **EXPORT/IMPORT**: JSON persistence for annotations across sessions\n" +
               "- ✅ **SEARCH CAPABILITY**: Find items by annotation content\n" +
               "- ✅ **AUTO-ANNOTATION**: Event-driven annotation with ProxyRequestHandler\n" +
               "- ✅ **100% MONTOYA COVERAGE**: All available annotation APIs utilized\n\n" +
               "### 📊 Technical Details\n" +
               "- **New Actions**: ANNOTATE_REPEATER, ANNOTATE_INTRUDER, ANNOTATE_SCANNER, ANNOTATE_WEBSOCKET, ANNOTATE_COLLABORATOR\n" +
               "- **Advanced Features**: EXPORT_ANNOTATIONS, IMPORT_ANNOTATIONS, SEARCH_BY_ANNOTATION\n" +
               "- **Event Handlers**: ENABLE_AUTO_ANNOTATION, DISABLE_AUTO_ANNOTATION with rule-based automation\n" +
               "- **Database Storage**: ConcurrentHashMap for components without direct annotation API\n" +
               "- **Full API Usage**: ProxyRequestHandler, ProxyWebSocketMessage, Annotations interfaces\n\n" +
               "## Version 1.7.38 - Enhanced Organizer with Full Montoya API (2025-08-28)\n\n" +
               "### 📂 OrganizerTool Complete Enhancement\n" +
               "- ✅ **FULL MONTOYA API**: All OrganizerItem methods now utilized\n" +
               "- ✅ **ITEM IDS & STATUS**: Shows ID and status (NEW, IN_PROGRESS, DONE, etc.)\n" +
               "- ✅ **ADVANCED FILTERING**: Filter by status, URL pattern, HTTP method\n" +
               "- ✅ **NEW ACTIONS**: LIST_ITEMS_FILTERED, GET_ITEM_BY_ID, GET_ITEM_STATUS\n" +
               "- ✅ **CUSTOM FILTERS**: Uses OrganizerItemFilter interface for flexible queries\n" +
               "- ✅ **DETAILED INSPECTION**: Full item details including headers, MIME type, timing\n" +
               "- ✅ **100% API COVERAGE**: All Organizer API features now exposed\n\n" +
               "### 📊 Technical Details\n" +
               "- **API Usage**: OrganizerItem.id(), status(), OrganizerItemFilter interface\n" +
               "- **Status Types**: NEW, IN_PROGRESS, POSTPONED, DONE, IGNORED\n" +
               "- **Filtering**: Combined filters with URL pattern, status, and method\n" +
               "- **Item Details**: Headers count, body size, MIME type, annotations\n\n" +
               "## Version 1.7.37 - Enhanced Scope Tool with Host Support (2025-08-28)\n\n" +
               "### 🎯 ScopeTool Major Enhancement\n" +
               "- ✅ **HOST SUPPORT**: Add entire hosts with all subdomains and protocols\n" +
               "- ✅ **SMART DETECTION**: Automatically detects host vs URL input\n" +
               "- ✅ **SCOPE TRACKING**: Monitor scope changes with timestamps\n" +
               "- ✅ **STATISTICS**: Track known in-scope/out-of-scope URLs\n" +
               "- ✅ **BULK OPERATIONS**: Add/check multiple URLs at once\n" +
               "- ✅ **SCOPE ANALYSIS**: Analyze proxy history for scope coverage\n" +
               "- ✅ **URL VARIATIONS**: Check HTTP/HTTPS, www/non-www variants\n" +
               "- ✅ **100% MONTOYA API**: Uses all available Scope API features\n\n" +
               "### 📊 Technical Details\n" +
               "- **API Usage**: Scope, ScopeChangeHandler, Registration interfaces\n" +
               "- **Host Addition**: Adds HTTP/HTTPS with wildcards for all subdomains\n" +
               "- **Change Tracking**: Queue-based history with 20 recent changes\n" +
               "- **Thread Safety**: ConcurrentLinkedQueue and synchronized sets\n" +
               "- **Automatic Normalization**: Handles missing protocols, www variations\n\n" +
               "## Version 1.7.36 - Enhanced Decoder with Full Montoya API Support (2025-08-28)\n\n" +
               "### 🔒 Decoder Tool Complete Rewrite\n" +
               "- ✅ **60+ HASH ALGORITHMS**: All Montoya DigestAlgorithm types supported\n" +
               "- ✅ **COMPRESSION**: GZIP, DEFLATE, BROTLI compress/decompress\n" +
               "- ✅ **ENCODING VARIANTS**: Base64 (URL-safe, no-padding), URL (all/key/unicode), HTML (decimal/hex)\n" +
               "- ✅ **SMART DECODE**: Auto-detect and decode multiple formats\n" +
               "- ✅ **FULL MONTOYA API**: Uses Base64Utils, URLUtils, HtmlUtils, CompressionUtils, CryptoUtils\n" +
               "- ✅ **MODERN HASHES**: BLAKE3, SHA3, KECCAK, RIPEMD, WHIRLPOOL, and more\n" +
               "- ✅ **100% API COVERAGE**: All encoding/decoding operations use native Montoya utilities\n\n" +
               "### 📊 Technical Details\n" +
               "- **Algorithms**: MD5, SHA family, SHA3 family, BLAKE2/3, RIPEMD, KECCAK, WHIRLPOOL, TIGER, SM3, GOST\n" +
               "- **Compression**: Full compress/decompress with size metrics\n" +
               "- **Smart Detection**: Automatic format detection for Base64, URL, HTML, Hex\n" +
               "- **API Integration**: Direct use of Montoya utility interfaces\n\n" +
               "## Version 1.7.35 - Streamlined Security Toolset (2025-08-27)\n\n" +
               "### 🧹 Tool Consolidation\n" +
               "- ❌ **REMOVED**: burp_macro_recorder tool - redundant functionality\n" +
               "- ✅ **RATIONALE**: All features already covered by existing tools:\n" +
               "  - Request replay: burp_repeater, burp_custom_http\n" +
               "  - Proxy history: burp_proxy_history\n" +
               "  - Session management: burp_session_management with native cookie jar\n" +
               "  - Variable substitution: Can be done in repeater/custom_http\n" +
               "- ✅ **NO NATIVE API**: Montoya API doesn't provide macro recording capabilities\n" +
               "- ✅ **CLEANER**: Reduced to 31 focused, high-value tools\n\n" +
               "### 📊 Technical Details\n" +
               "- **Tools Removed**: 1 (burp_macro_recorder)\n" +
               "- **New Tool Count**: 32 (from 34)\n" +
               "- **API Verification**: Confirmed no macro recording/creation/execution API\n" +
               "- **Impact**: Cleaner codebase without redundant simulated functionality\n\n" +
               "## Version 1.7.34 - Complete Session Management Fix (2025-08-27)\n\n" +
               "### 🔧 Critical Fixes\n" +
               "- ✅ **FIXED**: Session handler registration now persists across tool calls\n" +
               "- ✅ **FIXED**: Moved registration storage to McpServer static fields\n" +
               "- ✅ **FIXED**: AUTO_SESSION_STATUS now correctly shows active state\n" +
               "- ✅ **IMPROVED**: Token extraction with better patterns and false positive filtering\n" +
               "- ✅ **ENHANCED**: Focus on auth headers and Set-Cookie for token extraction\n\n" +
               "### 📊 Technical Details\n" +
               "- **Architecture**: Session handler stored in static fields at McpServer level\n" +
               "- **Pattern**: Better regex for tokens (hex strings, base64, JWT patterns)\n" +
               "- **Filtering**: Removes common false positives (URLs, HTML, dates, etc.)\n" +
               "- **Focus**: Extracts from Authorization, X-Auth, X-Session, Set-Cookie headers\n\n" +
               "## Version 1.7.33 - Session Handler Persistence Fix (2025-08-27)\n\n" +
               "### 🔧 Critical Fixes\n" +
               "- ✅ **FIXED**: Session handler registration now persists across tool calls\n" +
               "- ✅ **FIXED**: Moved registration storage to McpServer static fields\n" +
               "- ✅ **FIXED**: AUTO_SESSION_STATUS now correctly shows active state\n" +
               "- ✅ **IMPROVED**: Token extraction with better patterns and false positive filtering\n" +
               "- ✅ **ENHANCED**: Focus on auth headers and Set-Cookie for token extraction\n\n" +
               "### 📊 Technical Details\n" +
               "- **Architecture**: Session handler stored in static fields at McpServer level\n" +
               "- **Pattern**: Better regex for tokens (hex strings, base64, JWT patterns)\n" +
               "- **Filtering**: Removes common false positives (URLs, HTML, dates, etc.)\n" +
               "- **Focus**: Extracts from Authorization, X-Auth, X-Session, Set-Cookie headers\n\n" +
               "## Version 1.7.32 - Advanced Session Management with Native Cookie Jar (2025-08-27)\n\n" +
               "### 🍪 SessionManagementTool Complete Enhancement\n" +
               "- ✅ **NATIVE COOKIE JAR**: Full integration with Burp's CookieJar API\n" +
               "- ✅ **COOKIE_JAR_* ACTIONS**: List, set, delete, clear cookies in Burp's jar\n" +
               "- ✅ **AUTO SESSION HANDLER**: Register custom SessionHandlingAction with Burp\n" +
               "- ✅ **SESSION ANALYSIS**: Keyword-based validity detection without auth errors\n" +
               "- ✅ **PROPER COOKIE OBJECTS**: Uses Cookie interface for domain/path/expiration\n" +
               "- ✅ **9 NEW ACTIONS**: COOKIE_JAR_LIST/SET/DELETE/CLEAR, ENABLE/DISABLE_AUTO_SESSION, etc.\n" +
               "- ✅ **FULL AUTOMATION**: Integrates with Burp's session handling rules\n\n" +
               "### 📊 Technical Details\n" +
               "- **API Usage**: CookieJar, SessionHandlingAction, Cookie interfaces\n" +
               "- **Cookie Management**: Proper domain/path/expiration handling\n" +
               "- **Session Handler**: Custom handler with request/refresh/failure tracking\n" +
               "- **Keyword Analysis**: Simple string search replacing ResponseKeywordsAnalyzer\n" +
               "- **Known Issue**: Handler registration doesn't persist across tool calls\n\n" +
               "## Version 1.7.31 - Streamlined Toolset (2025-08-27)\n\n" +
               "### 🧹 Tool Removal\n" +
               "- ❌ **REMOVED**: burp_issue_templates tool - unnecessary generic templates\n" +
               "- ✅ **CLEANER**: Reduced to 33 focused, high-value tools\n" +
               "- ✅ **RATIONALE**: Generic templates provide no real value for actual testing\n" +
               "- ✅ **BETTER**: Scanner and add_issue already create properly formatted issues\n\n" +
               "### 📊 Technical Details\n" +
               "- **Tools Removed**: 1 (burp_issue_templates)\n" +
               "- **New Tool Count**: 33 (from 34)\n" +
               "- **Code Cleaned**: Removed dead code that wasn't integrated with other tools\n" +
               "- **Impact**: Cleaner, more maintainable codebase\n\n" +
               "## Version 1.7.30 - Single Request Scanning (2025-08-27)\n\n" +
               "### 🎯 NEW: SCAN_SPECIFIC_REQUEST Action\n" +
               "- ✅ **NEW ACTION**: SCAN_SPECIFIC_REQUEST for single-URL scanning without spidering\n" +
               "- ✅ **PRECISE SCANNING**: Mimics Burp's 'Scan this URL' right-click behavior\n" +
               "- ✅ **NO LINK FOLLOWING**: Tests only the specific request provided\n" +
               "- ✅ **FULL COVERAGE**: Scans all insertion points (headers, cookies, parameters, body)\n" +
               "- ✅ **CUSTOM REQUESTS**: Accept raw HTTP request with host/port/protocol parameters\n" +
               "- ✅ **ACTIVE/PASSIVE**: Support both scan modes for flexibility\n\n" +
               "### 📊 Technical Details\n" +
               "- **Root Cause**: ADD_TO_SCAN with URL was following links due to LEGACY_ACTIVE_AUDIT_CHECKS\n" +
               "- **Solution**: New action that adds specific HttpRequest without spider behavior\n" +
               "- **Impact**: Enables precise single-endpoint vulnerability testing\n" +
               "- **API Usage**: HttpService.httpService() with explicit host/port/protocol\n\n" +
               "## Version 1.7.29 - Filter JSON Parsing Fix (2025-08-26)\n\n" +
               "### 🔧 Critical Fix for IssueFromProxyTool\n" +
               "- ✅ **FIXED**: Filters parameter now properly parsed when received as JSON string\n" +
               "- ✅ **ENHANCED**: LogsTool can capture logs directly via static methods\n" +
               "- ✅ **WORKING**: All filter types (method, contains, parameter, etc.) now work correctly\n" +
               "- ✅ **VERIFIED**: POST requests correctly attached to issues instead of GET\n" +
               "- ✅ **IMPROVED**: Comprehensive debug logging for troubleshooting filter issues\n\n" +
               "### 📊 Technical Details\n" +
               "- **Root Cause**: MCP sends filters as JSON string, not JsonNode object\n" +
               "- **Solution**: Added JSON string detection and parsing in IssueFromProxyTool\n" +
               "- **Impact**: All filter-based issue creation now works as intended\n" +
               "- **Architecture**: Clean delegation from IssueFromProxyTool to ProxyHistoryTool\n\n" +
               "## Version 1.7.21 - Dynamic Filter Enhancement (2025-08-26)\n\n" +
               "### 🔍 IssueFromProxyTool Dynamic Filtering\n" +
               "- ✅ **DYNAMIC FILTERS**: Accept any ProxyHistoryTool filter via filters object\n" +
               "- ✅ **PARAMETER FILTERING**: Find requests with specific parameters\n" +
               "- ✅ **CONTENT SEARCH**: Filter by text in request/response\n" +
               "- ✅ **COOKIE FILTERING**: Match requests with specific cookies\n" +
               "- ✅ **STATUS FILTERING**: Filter by response status codes\n" +
               "- ✅ **COMBINED FILTERS**: Apply multiple filters simultaneously\n" +
               "- ✅ **BACKWARD COMPATIBLE**: Still supports simple method parameter\n\n" +
               "## Version 1.7.20 - ProxyHistory ID Preservation (2025-08-26)\n\n" +
               "### 🔧 ProxyHistoryTool Enhancement\n" +
               "- ✅ **ID PRESERVATION**: Filtered results now preserve original proxy entry IDs\n" +
               "- ✅ **HELPER CLASS**: Added FilteredResults to track original indices\n" +
               "- ✅ **METHOD FILTER**: IssueFromProxyTool can filter by HTTP method\n" +
               "- ✅ **ACCURATE TRACKING**: Original entry numbers maintained in all views\n\n" +
               "## Version 1.7.19 - Enhanced Crawler with Full Tracking (2025-08-26)\n\n" +
               "### 🕷️ CrawlerTool Complete Rewrite\n" +
               "- ✅ **FULL TRACKING**: Complete crawl lifecycle management with unique IDs\n" +
               "- ✅ **5 ACTIONS**: START_CRAWL, GET_STATUS, CANCEL_CRAWL, LIST_CRAWLS, CLEAR_CRAWLS\n" +
               "- ✅ **PROGRESS MONITORING**: Real-time request count, error tracking, status messages\n" +
               "- ✅ **PERFORMANCE METRICS**: Requests per second, error rates, duration tracking\n" +
               "- ✅ **CRAWL MANAGEMENT**: Cancel running crawls, clear completed crawls\n" +
               "- ✅ **DETAILED STATUS**: Comprehensive progress reports with timing and metrics\n" +
               "- ✅ **METADATA TRACKING**: Target URLs, start time, depth configuration\n" +
               "- ✅ **THREAD-SAFE**: ConcurrentHashMap for safe multi-crawl management\n\n" +
               "## Version 1.7.18 - Scanner MCP Format Fix (2025-08-26)\n\n" +
               "### 🔧 Critical Fix for ScannerTool\n" +
               "- ✅ **FIXED**: ScannerTool now returns MCP-compliant array format\n" +
               "- ✅ **ERROR RESOLVED**: Fixed 'Expected array, received object' validation error\n" +
               "- ✅ **RESPONSE FORMAT**: createTextResponse and createErrorResponse now return content arrays\n" +
               "- ✅ **ALL ACTIONS FIXED**: START_SCAN, GET_STATUS, GET_ISSUES, etc. all return correct format\n\n" +
               "## Version 1.7.17 - Enhanced ScanStatusTool (2025-08-26)\n\n" +
               "### 🚀 ScanStatusTool Major Enhancement\n" +
               "- ✅ **ACTIVE SCAN TRACKING**: Real-time monitoring of running scans with live metrics\n" +
               "- ✅ **SCAN METRICS**: Detailed performance analytics and efficiency tracking\n" +
               "- ✅ **ADVANCED FILTERING**: URL wildcards, severity, in-scope filtering\n" +
               "- ✅ **SCAN HISTORY**: Track completed and active scans\n" +
               "- ✅ **CROSS-REFERENCE**: Link issues to their originating scans\n" +
               "- ✅ **SMART STATUS DETECTION**: Intelligent scan completion detection\n" +
               "- ✅ **ROBUST ERROR HANDLING**: Graceful reflection access with detailed logging\n" +
               "- ✅ **5 NEW ACTIONS**: ACTIVE_SCANS, SCAN_METRICS, FILTER_ISSUES, SCAN_HISTORY, METRICS view\n\n" +
               "## Version 1.7.16 - Scanner Tool Full Montoya API (2025-08-26)\n\n" +
               "### 🚀 Scanner Tool Complete Rewrite - 100% Montoya API Coverage\n" +
               "- ✅ **SCAN TRACKING**: Full scan lifecycle management with unique IDs\n" +
               "- ✅ **TARGETED SCANNING**: Insertion points for specific parameter scanning (like Burp UI)\n" +
               "- ✅ **9 ACTIONS**: START_SCAN, GET_STATUS, GET_ISSUES, CANCEL_SCAN, LIST_SCANS, ADD_TO_SCAN, GENERATE_REPORT, IMPORT_BCHECK, CLEAR_ISSUES\n" +
               "- ✅ **PROGRESS MONITORING**: Track requests, insertion points, errors in real-time\n" +
               "- ✅ **BCHECK SUPPORT**: Import custom vulnerability definitions\n" +
               "- ✅ **REPORT GENERATION**: Export scan results to HTML/XML\n" +
               "- ✅ **CRAWL INTEGRATION**: Optional crawling with scans\n" +
               "- ✅ **STATE MANAGEMENT**: Thread-safe tracking with ConcurrentHashMap\n" +
               "- ✅ **API LIMITATIONS HANDLED**: Graceful handling of runtime limitations\n\n" +
               "## Version 1.7.15 - GlobalInterceptor Complete Fix (2025-08-26)\n\n" +
               "### 🔧 Critical Fixes for GlobalInterceptorTool\n" +
               "- ✅ **TOOL FILTER FIXED**: Proper JSON array parsing and tool validation\n" +
               "- ✅ **TIMING DATA FIXED**: Now shows actual response times (ms) not timestamps\n" +
               "- ✅ **RATE LIMITING FIXED**: Handles Integer/Number/String types correctly\n" +
               "- ✅ **EXPORT RULES FIXED**: Returns MCP-compliant text format with JSON\n" +
               "- ✅ **RESET FILTER ADDED**: New action to restore all tools when filter fails\n" +
               "- ✅ **ERROR HANDLING**: Better validation and reporting of invalid tools\n" +
               "- ✅ **MEMORY MANAGEMENT**: Cleans up timing data to prevent leaks\n\n" +
               "## Version 1.7.14 - Optimized Global Interceptor (2025-08-26)\n\n" +
               "### 🚀 GlobalInterceptorTool Complete Optimization\n" +
               "- ✅ **WEBSOCKET API**: Now uses api.websockets() for TRUE global WebSocket interception\n" +
               "- ✅ **DROP SUPPORT**: Can drop WebSocket messages with TextMessageAction.drop()\n" +
               "- ✅ **REGEX RULES**: Full regex support for pattern matching and replacement\n" +
               "- ✅ **TOOL FILTERING**: Filter which Burp tools are affected (Scanner, Intruder, etc.)\n" +
               "- ✅ **RATE LIMITING**: Configurable delays between requests\n" +
               "- ✅ **TIMING DATA**: Capture and analyze response times\n" +
               "- ✅ **RULE PRIORITIES**: Execute rules in priority order\n" +
               "- ✅ **IMPORT/EXPORT**: Save and restore rule configurations\n" +
               "- ✅ **ENHANCED STATS**: Track drops, modification rates, timing averages\n\n" +
               "## Version 1.7.13 - ProxyInterceptorTool Complete (2025-08-26)\n\n" +
               "### 🚀 ProxyInterceptorTool Full Montoya API Coverage\n" +
               "- ✅ **RESPONSE INTERCEPTION**: Full response modification queue with event-driven decisions\n" +
               "- ✅ **WEBSOCKET SUPPORT**: WebSocket creation handler and message interception\n" +
               "- ✅ **WEBSOCKET HISTORY**: Access WebSocket proxy history\n" +
               "- ✅ **NEW ACTIONS**: get_response_queue, modify_response, forward_response, drop_response\n" +
               "- ✅ **NEW ACTIONS**: get_websocket_queue, get_websocket_history\n" +
               "- ✅ **100% COVERAGE**: All Montoya Proxy API features now implemented\n\n" +
               "## Version 1.7.12 - ProxyInterceptorTool Enhanced (2025-08-26)\n\n" +
               "### 🔧 ProxyInterceptorTool Improvements\n" +
               "- ✅ **CRITICAL FIX**: Proper Registration management - handlers now deregister correctly\n" +
               "- ✅ **NEW**: Master intercept control - control Burp's UI intercept button\n" +
               "- ✅ **NEW**: Added master_intercept_on/off/status actions\n" +
               "- ✅ **FIXED**: Memory leak from handler accumulation\n" +
               "- ✅ **MAINTAINED**: Event-driven architecture for MCP decisions\n\n" +
               "## Version 1.7.11 - RepeaterTool Refactor (2025-08-26)\n\n" +
               "### 🔧 RepeaterTool Pure Montoya API\n" +
               "- ✅ **REFACTORED**: RepeaterTool now uses only Montoya Repeater API\n" +
               "- ✅ **REMOVED**: HTTP execution functionality moved to other tools\n" +
               "- ✅ **SEND_TO_REPEATER**: Create and send new requests to Repeater tabs\n" +
               "- ✅ **SEND_FROM_PROXY**: Send proxy history items to Repeater\n" +
               "- ✅ **CLEARER PURPOSE**: Tool now focused solely on Repeater tab management\n\n" +
               "## Version 1.7.10 - ProxyHistory Optimization (2025-08-25)\n\n" +
               "### 🚀 ProxyHistoryTool Complete Rewrite\n" +
               "- ✅ **OPTIMIZED**: Full Montoya API usage for proxy history access\n" +
               "- ✅ **ADVANCED FILTERING**: 20+ filter options including regex, status, timing\n" +
               "- ✅ **PERFORMANCE**: Efficient handling of large proxy histories\n" +
               "- ✅ **ANNOTATIONS**: Full support for notes and highlight colors\n\n" +
               "## Version 1.7.9 - WebSocket Global Interceptor & Enhanced Intruder (2025-08-22)\n\n" +
               "### 🌐 NEW: Global WebSocket Interception\n" +
               "- ✅ **GlobalInterceptorTool Enhanced**: Added WebSocket match/replace functionality\n" +
               "- ✅ **Enhanced IntruderTool**: Advanced payload processors and generators\n" +
               "- ✅ **Bug Fixes**: Fixed CustomHttpTool response wrapping for MCP compatibility\n" +
               "- ✅ **34 TOTAL TOOLS**: Complete comprehensive security testing toolkit\n\n" +
               "### 🌐 WebSocket Tool Features\n" +
               "- ✅ **Create Connections**: Programmatically create WebSocket connections\n" +
               "- ✅ **Send Messages**: Send text/binary messages to active connections\n" +
               "- ✅ **View History**: Monitor WebSocket traffic and proxy history\n" +
               "- ✅ **Connection Management**: List, close, and manage multiple connections\n\n" +
               "### 🔍 Response Analyzer Features\n" +
               "- ✅ **Keyword Analysis**: Find sensitive data and error messages\n" +
               "- ✅ **Variation Detection**: Identify dynamic content areas\n" +
               "- ✅ **Reflection Points**: Detect potential XSS vulnerabilities\n" +
               "- ✅ **Complete Analysis**: Run all three analyses at once\n\n" +
               "### 🛠️ Utilities Tool Features\n" +
               "- ✅ **Encoding/Decoding**: Base64, URL, HTML encode/decode\n" +
               "- ✅ **Hashing**: MD5, SHA1, SHA256, SHA384, SHA512\n" +
               "- ✅ **Random Data**: Generate bytes, alphanumeric, hex data\n" +
               "- ✅ **Compression**: GZIP compress/decompress\n" +
               "- ✅ **JSON**: Beautify and format JSON data\n" +
               "- ✅ **String Operations**: Case conversion, reverse, capitalize\n\n" +
               "## Version 1.7.6 - Logging Tools Enhanced (2025-08-21)\n\n" +
               "### 🔍 NEW: LogsTool\n" +
               "- ✅ **NEW TOOL**: burp_logs - Access and manage extension logs\n" +
               "- ✅ **WRITE LOGS**: Add messages to Burp's output/error logs\n" +
               "- ✅ **READ LOGS**: Retrieve captured log entries with filtering\n" +
               "- ✅ **RAISE EVENTS**: Create debug/info/error/critical events\n" +
               "- ✅ **30 TOOLS**: Complete toolkit for security testing\n\n" +
               "## Version 1.7.5 - Documentation Complete (2025-08-21)\n\n" +
               "### 📚 Full Documentation\n" +
               "- ✅ **README**: Updated with CustomHttpTool in tools list\n" +
               "- ✅ **USAGE TOOL**: Added comprehensive documentation and examples\n" +
               "- ✅ **TEST SUITE**: Created test_custom_http.sh with all features\n" +
               "- ✅ **29 TOOLS**: Complete toolkit with HTTP operations consolidated\n\n" +
               "## Version 1.7.4 - Complete HTTP Tool Fix (2025-08-21)\n\n" +
               "### 🎉 CustomHttpTool Fully Working\n" +
               "- ✅ **HELPER METHOD**: Created createHttpRequest() for consistent parsing\n" +
               "- ✅ **PARALLEL FIXED**: All request types now use proper HttpService\n" +
               "- ✅ **TESTED**: Basic requests confirmed working\n" +
               "- ✅ **READY**: All 8 actions should now function correctly\n\n" +
               "## Version 1.7.3 - Fix HttpRequest Creation (2025-08-21)\n\n" +
               "### 🔧 Critical Fix\n" +
               "- ✅ **FIXED**: HttpRequest now created with HttpService parameter\n" +
               "- ✅ **PARSING**: Extract host, port, and protocol from request\n" +
               "- ✅ **WORKING**: CustomHttpTool should now properly send requests\n\n" +
               "## Version 1.7.2 - Remove HTTP Caching (2025-08-21)\n\n" +
               "### 🔧 Bug Fix\n" +
               "- ✅ **REMOVED**: Cached HTTP service field that was causing null issues\n" +
               "- ✅ **DIRECT API**: All calls now use api.http() directly\n" +
               "- ✅ **SIMPLIFIED**: Cleaner implementation without unnecessary caching\n\n" +
               "## Version 1.7.1 - HTTP Service Fix (2025-08-21)\n\n" +
               "### 🔧 Bug Fix\n" +
               "- ✅ **FIXED**: HTTP service null reference in CustomHttpTool\n" +
               "- ✅ **IMPROVED**: Direct API calls instead of cached reference\n" +
               "- ✅ **ADDED**: Null checks and error handling\n\n" +
               "## Version 1.7.0 - Comprehensive HTTP Interface (2025-08-21)\n\n" +
               "### 🚀 NEW: Custom HTTP Tool\n" +
               "- ✅ **NEW TOOL**: burp_custom_http - Complete HTTP interface implementation\n" +
               "- ✅ **SINGLE REQUESTS**: Full control with HTTP modes and connection IDs\n" +
               "- ✅ **PARALLEL REQUESTS**: Batch operations for race conditions and performance\n" +
               "- ✅ **RESPONSE ANALYSIS**: Keyword detection and variation analysis\n" +
               "- ✅ **SESSION HANDLERS**: Custom session management rules\n" +
               "- ✅ **HTTP/2 SUPPORT**: Control HTTP/1.1 vs HTTP/2 modes\n" +
               "- ✅ **ADVANCED OPTIONS**: Redirects, connection control, request options\n" +
               "- ✅ **29 TOTAL TOOLS**: Most comprehensive Burp MCP Bridge yet\n\n" +
               "### 🎯 CustomHttpTool Features\n" +
               "- ✅ **Actions**: SEND_REQUEST, SEND_PARALLEL, ANALYZE_KEYWORDS, ANALYZE_VARIATIONS\n" +
               "- ✅ **Session**: REGISTER_SESSION_HANDLER, LIST/UNREGISTER handlers\n" +
               "- ✅ **Cookies**: GET_COOKIES, SET_COOKIE operations\n" +
               "- ✅ **Full Montoya HTTP**: Complete api.http() interface coverage\n" +
               "- ✅ **LLM Optimized**: Single tool for all HTTP operations\n\n" +
               "## Version 1.6.0 - Self-Documenting Usage Tool (2025-08-17)\n\n" +
               "### 📚 Self-Documentation Features\n" +
               "- ✅ **NEW TOOL**: burp_usage - Query documentation without external files\n" +
               "- ✅ **COMPLETE COVERAGE**: All 29 tools documented with parameters\n" +
               "- ✅ **INTERACTIVE DISCOVERY**: Search tools by keyword\n" +
               "- ✅ **AI-FRIENDLY**: Perfect for LLMs to learn tool usage\n\n" +
               "## Version 1.4.1 - Proxy Interceptor (2025-08-17)\n\n" +
               "### 🔀 NEW: Proxy Interceptor Tool\n" +
               "- ✅ **NEW TOOL**: burp_proxy_interceptor - Intercept and modify proxy traffic\n" +
               "- ✅ **RULE-BASED**: Define patterns to match and modify requests\n" +
               "- ✅ **REAL-TIME**: Modifications applied automatically as traffic flows\n" +
               "- ✅ **HEADER INJECTION**: Add/remove headers based on patterns\n" +
               "- ✅ **BODY MODIFICATION**: Replace or search/replace in request bodies\n" +
               "- ✅ **UI INTERCEPT**: Optionally show in Burp's Intercept tab\n" +
               "- ✅ **DROP REQUESTS**: Block matching requests from being sent\n" +
               "- ✅ **HIGHLIGHTING**: Color-code modified requests\n" +
               "- ✅ **26 TOTAL TOOLS**: Expanding the security testing toolkit\n\n" +
               "### 🎯 Interceptor Features\n" +
               "- ✅ **Pattern Matching**: URL regex, HTTP method, header patterns\n" +
               "- ✅ **Modification Actions**: Headers, body, intercept, drop\n" +
               "- ✅ **Rule Management**: Add, update, remove, enable/disable rules\n" +
               "- ✅ **Statistics Tracking**: Count intercepted and modified requests\n" +
               "- ✅ **Proxy-Only Scope**: Affects browser traffic, not other tools\n\n" +
               "## Version 1.4.0 - Professional Issue Grouping (2025-08-09)\n\n" +
               "### 🎯 Native-Style Issue Grouping\n" +
               "- ✅ **NEW**: AddIssueTool with intelligent issue type grouping\n" +
               "- ✅ **ORGANIZED**: Issues grouped by type like Burp's native scanner\n" +
               "- ✅ **50+ MAPPINGS**: Automatic normalization of issue type variations\n" +
               "- ✅ **CLEAN PRESENTATION**: Professional issue list organization\n" +
               "- ✅ **BACKWARD COMPATIBLE**: Existing scripts continue to work\n\n" +
               "## Version 1.3.9 - Advanced Security Visualizations (2025-08-08)\n\n" +
               "### 🎨 12 Interactive Visualizations\n" +
               "- ✅ **NEW TOOL**: burp_enhanced_sitemap_export - Comprehensive data extraction\n" +
               "- ✅ **RISK MATRIX**: Severity vs Confidence bubble chart\n" +
               "- ✅ **DATA FLOW**: Sankey diagram visualization\n" +
               "- ✅ **3D GLOBE**: Three.js spatial attack surface\n" +
               "- ✅ **DEPENDENCIES**: Chord diagram relationships\n" +
               "- ✅ **ATTACK PATHS**: Exploitation chain visualization\n" +
               "- ✅ **And 6 more**: Security headers, parallel coords, stack layers, etc.\n\n" +
               "### 🐛 Critical Fixes\n" +
               "- ✅ **FIXED**: getToolInstance() registration for async handling\n" +
               "- ✅ **FIXED**: API compatibility with Burp runtime\n" +
               "- ✅ **DOCUMENTED**: Two-place registration requirement\n\n" +
               "## Version 1.3.8 - Site Map Export & Visualization (2025-08-07)\n\n" +
               "### 🗺️ Site Map Export Tool\n" +
               "- ✅ **NEW TOOL**: burp_sitemap_export - Export site map for interactive HTML visualization\n" +
               "- ✅ **INTERACTIVE GRAPH**: D3.js-powered draggable, zoomable site map\n" +
               "- ✅ **VULNERABILITY MAPPING**: Color-coded nodes based on discovered vulnerabilities\n" +
               "- ✅ **HIERARCHICAL STRUCTURE**: Visual representation of site relationships\n" +
               "- ✅ **JSON FORMAT**: Compatible with burp-site-map.html visualization tool\n" +
               "- ✅ **NODE TYPES**: root, directory, file, form, api, admin\n" +
               "- ✅ **COLOR CODING**: Red (high), Orange (medium), Yellow (low), Blue (info), Green (safe)\n\n" +
               "## Version 1.3.7 - Passive Scanning Support (2025-08-07)\n\n" +
               "### 🔎 Passive Scanning Added\n" +
               "- ✅ **NEW**: Scanner now supports PASSIVE mode for safe analysis without attacks\n" +
               "- ✅ **MODE PARAMETER**: Choose between ACTIVE (attacks) or PASSIVE (no attacks)\n" +
               "- ✅ **SAFE FOR PRODUCTION**: Passive mode analyzes without sending payloads\n" +
               "- ✅ **DASHBOARD VISIBLE**: Both scan types appear in Burp Suite dashboard\n\n" +
               "## Version 1.3.6 - Scanner and Crawler Improvements (2025-08-07)\n\n" +
               "### 🎯 Scanner/Crawler Fixes\n" +
               "- ✅ **FIXED**: Scanner now properly starts active vulnerability scans with attack payloads\n" +
               "- ✅ **IMPROVED**: Clear distinction between active scanning and passive crawling\n" +
               "- ✅ **ENHANCED**: Scanner uses correct Montoya API (LEGACY_ACTIVE_AUDIT_CHECKS)\n" +
               "- ✅ **CLARIFIED**: Tool descriptions explain active vs passive operations\n\n" +
               "### 🔄 MCP Response Format\n" +
               "- ✅ **FIXED**: SiteMapAnalysisTool returns MCP-compliant array format\n" +
               "- ✅ **RESOLVED**: Fixed 'Expected array, received object' error\n\n" +
               "## Version 1.3.5 - Site Map Analysis Added (2025-08-07)\n\n" +
               "### 🗺️ NEW: Site Map Analysis Tool\n" +
               "- ✅ **NEW TOOL**: burp_sitemap_analysis - Comprehensive site map analysis\n" +
               "- ✅ **STRUCTURE ANALYSIS**: Directory tree, file types, depth analysis\n" +
               "- ✅ **TECHNOLOGY DETECTION**: Stack fingerprinting, CMS detection\n" +
               "- ✅ **ATTACK SURFACE MAPPING**: Parameters, forms, upload endpoints\n" +
               "- ✅ **CONTENT ANALYSIS**: Sensitive data detection, comments\n" +
               "- ✅ **RESPONSE STATISTICS**: Status codes, MIME types, sizes\n" +
               "- ✅ **ISSUE CORRELATION**: Vulnerability mapping by location\n" +
               "- ✅ **FULL ANALYSIS**: Complete site overview in one command\n\n" +
               "### 📊 Tool Count\n" +
               "- ✅ **23 ACTIVE TOOLS**: Added site map analysis\n" +
               "- ⚠️ **NOTE**: burp_mcp_storage remains disabled\n\n" +
               "## Version 1.3.4 - MCP Storage Disabled (2025-08-07)\n\n" +
               "### 🔧 Configuration Change\n" +
               "- ⚠️ **DISABLED**: burp_mcp_storage temporarily disabled from MCP visibility\n" +
               "- ✅ **CODE INTACT**: All storage functionality preserved in codebase\n" +
               "- ✅ **RE-ENABLE**: Uncomment line 97 in McpServer.java to restore\n" +
               "- ✅ **TOOL COUNT**: Now 22 active tools (was 23)\n\n" +
               "### 📝 Reason\n" +
               "- Storage tool temporarily disabled per user request\n" +
               "- Can be re-enabled by uncommenting registration in McpServer.java\n" +
               "- All code remains unchanged for easy restoration\n\n" +
               "## Version 1.3.3 - Annotation Support (2025-08-06)\n\n" +
               "### 🎨 NEW: Annotation Tool\n" +
               "- ✅ **NEW TOOL**: burp_annotate - Add annotations and highlights to proxy entries\n" +
               "- ✅ **VISUAL ORGANIZATION**: 9 highlight colors for categorizing findings\n" +
               "- ✅ **NOTES SUPPORT**: Add detailed notes to any proxy history entry\n" +
               "- ✅ **BULK OPERATIONS**: Annotate multiple entries by URL pattern\n" +
               "- ✅ **FILTERING**: Retrieve and filter annotated entries\n" +
               "- ✅ **23 TOTAL TOOLS**: Enhanced security testing toolkit\n\n" +
               "### 🔧 Technical Updates\n" +
               "- ✅ **MONTOYA API**: Leveraging Annotations interface from API 2025.8\n" +
               "- ✅ **FULL AUTOMATION**: All annotation operations fully automated\n" +
               "- ✅ **COLOR SUPPORT**: RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY\n\n" +
               "## Version 1.3.2 - Full Organizer Support (2025-08-06)\n\n" +
               "### 🔧 API Update\n" +
               "- ✅ **UPDATED**: Montoya API to version 2025.8\n" +
               "- ✅ **RESTORED**: Full items() method support in Organizer\n" +
               "- ✅ **FIXED**: LIST_ITEMS and GET_ITEM_COUNT now fully functional\n" +
               "- ✅ **ENHANCED**: Complete Organizer tool with all features working\n\n" +
               "## Version 1.3.1 - Organizer Integration (2025-08-06)\n\n" +
               "### 📂 NEW: Organizer Tool\n" +
               "- ✅ **NEW TOOL**: burp_organizer - Manage and organize HTTP requests/responses\n" +
               "- ✅ **SEND TO ORGANIZER**: Add requests to Burp's Organizer tool\n" +
               "- ✅ **LIST ITEMS**: View all organized items with details\n" +
               "- ✅ **GET ITEM COUNT**: Check how many items are in the Organizer\n" +
               "- ✅ **PROXY INTEGRATION**: Send items directly from proxy history\n" +
               "- ✅ **22 TOTAL TOOLS**: Complete security testing toolkit expanded\n\n" +
               "### 🎯 Organizer Features\n" +
               "- ✅ **Flexible Input**: Create new requests or send from proxy history\n" +
               "- ✅ **Rich Details**: Shows method, URL, status, response length, timing\n" +
               "- ✅ **Workflow Integration**: Organize interesting requests during testing\n" +
               "- ✅ **Easy Management**: View and manage items in Burp's Organizer tab\n\n" +
               "## Version 1.3.0 - MCP Storage Auto-ID (2025-07-31)\n\n" +
               "### 🗄️ NEW: MCP Storage Integration\n" +
               "- ✅ **NEW TOOL**: burp_mcp_storage - Store/retrieve request/response pairs by identifier\n" +
               "- ✅ **CONTEXT MENU**: Right-click any request/response → Send to MCP Bridge\n" +
               "- ✅ **AUTO-ID GENERATION**: Automatic IDs follow pattern: method_endpoint_timestamp_counter\n" +
               "- ✅ **BATCH SUPPORT**: Send multiple items at once with batch_timestamp_N pattern\n" +
               "- ✅ **NO DIALOGS**: Streamlined workflow - just right-click and send\n\n" +
               "### 🎯 Auto-ID Features\n" +
               "- ✅ **Meaningful IDs**: get_login_153042_1, post_api_users_153105_2\n" +
               "- ✅ **Smart Extraction**: Uses endpoint name from URL path\n" +
               "- ✅ **Timestamp Tracking**: HHMMSS format shows when stored\n" +
               "- ✅ **Unique Counter**: Prevents ID collisions\n" +
               "- ✅ **Success Dialog**: Shows copyable ID for easy reference\n\n" +
               "### 📚 Tool Capabilities\n" +
               "- ✅ **Actions**: get (retrieve by ID), list (show all), clear (remove all)\n" +
               "- ✅ **Storage**: In-memory ConcurrentHashMap (thread-safe)\n" +
               "- ✅ **21 Total Tools**: Complete security testing toolkit\n\n" +
               "## Version 1.2.4 - Bambda Hotfix (2025-07-29)\n\n" +
               "### 🔧 Critical Fix\n" +
               "- ✅ **FIXED**: burp_bambda tool now properly registered in async handler\n" +
               "- ✅ **RESOLVED**: Added missing case in getToolInstance() method\n" +
               "- ✅ **VERIFIED**: All Bambda functionality now working correctly\n\n" +
               "## Version 1.2.3 - Bambda Intelligence Update (2025-07-29)\n\n" +
               "### 🎭 NEW: Bambda Advanced Filtering Tool\n" +
               "- ✅ **NEW TOOL**: burp_bambda - Apply intelligent Java-based filters\n" +
               "- ✅ **10 PRESETS**: Authenticated requests, API endpoints, SQL injection candidates, etc.\n" +
               "- ✅ **CUSTOM FILTERS**: Create complex Java-based traffic filters\n" +
               "- ✅ **FULLY AUTOMATED**: Filters apply instantly to proxy history\n\n" +
               "### 🤖 Enhanced Agent Intelligence\n" +
               "- ✅ **CLEAR DESCRIPTIONS**: All tools now state automation level (FULLY AUTOMATED/MANUAL REQUIRED)\n" +
               "- ✅ **USAGE EXAMPLES**: Added comprehensive workflow documentation\n" +
               "- ✅ **AGENT PROMPTS**: System prompts to help agents use tools effectively\n" +
               "- ✅ **BETTER GUIDANCE**: Tool count increased to 20 with clear capabilities\n\n" +
               "### 🔧 Intruder Tool Fix\n" +
               "- ✅ **FIXED**: Intruder now properly handles POST requests with body data\n" +
               "- ✅ **ENHANCED**: Supports custom headers and attack positions (§markers§)\n" +
               "- ✅ **IMPROVED**: Shows method, body length, and headers in confirmation\n" +
               "- ✅ **NOTE**: Still requires manual payload configuration in Burp UI\n\n" +
               "### 📚 Documentation Updates\n" +
               "- ✅ **TOOL_CAPABILITIES.md**: Complete list of what each tool can/cannot do\n" +
               "- ✅ **AGENT_USAGE_EXAMPLES.md**: Real-world workflows and examples\n" +
               "- ✅ **AGENT_SYSTEM_PROMPT.md**: Copy-paste prompts for different scenarios\n" +
               "- ✅ **Project Reorganization**: Cleaner directory structure\n\n" +
               "## Version 1.2.2 - Issue Creation Enhancement (2025-07-29)\n\n" +
               "### 🐛 Critical Bug Fix: Issue Creation\n" +
               "- ✅ **FIXED**: Issues now show actual exploit requests instead of generic GET /\n" +
               "- ✅ **ENHANCED**: Accept raw request/response data for accurate context\n" +
               "- ✅ **IMPROVED**: Multi-strategy proxy history matching (URL, method+path, parameters)\n" +
               "- ✅ **ADDED**: New parameters: request, response, method, path, parameters\n\n" +
               "### 🎯 Universal Vulnerability Support\n" +
               "- ✅ **SQL Injection**: Preserves POST requests with injection payloads\n" +
               "- ✅ **XSS**: Maintains GET/POST requests with script tags\n" +
               "- ✅ **Command Injection**: Shows actual command execution requests\n" +
               "- ✅ **Path Traversal**: Keeps directory traversal attempts intact\n" +
               "- ✅ **All Vulnerability Types**: Works for any security finding\n\n" +
               "### 🔍 Enhanced Proxy History Matching\n" +
               "- ✅ **Priority 1**: Exact URL matching\n" +
               "- ✅ **Priority 2**: Method + Path matching\n" +
               "- ✅ **Priority 3**: Path + Parameters matching\n" +
               "- ✅ **Priority 4**: Host + Path partial matching\n" +
               "- ✅ **Better Logging**: Detailed search progress in Burp logs\n\n" +
               "### 🔧 API Compatibility Fixes\n" +
               "- ✅ **Updated**: All tools use finalRequest() instead of deprecated request()\n" +
               "- ✅ **Fixed**: IssueFromProxyTool updated to modern Montoya API\n" +
               "- ✅ **Verified**: Full compatibility with Montoya API 2025.7\n\n" +
               "### 📋 Issue Quality Improvements\n" +
               "- ✅ **Context Preservation**: Issues include actual exploit requests/responses\n" +
               "- ✅ **Parameter Display**: Shows vulnerable parameters in issue details\n" +
               "- ✅ **Request Truncation**: Prevents oversized request data in descriptions\n" +
               "- ✅ **No Generic Requests**: Eliminates misleading fallback requests\n\n" +
               "### 🔄 Previous Releases\n" +
               "- v1.2.1: Java 17 modernization with enhanced issue creation tools\n" +
               "- v1.2.0: Scanner/Repeater enhancements, incremental naming\n" +
               "- v1.1.0: URL encoding fixes, async handling, proxy casting\n" +
               "- v1.0.0: Initial release with 19 comprehensive tools";
    }
}
