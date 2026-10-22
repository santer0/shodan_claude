export default async function handler(req, res) {
  // 1. Configuración de CORS y cabeceras MCP
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-mcp-protocol-version, authorization, x-api-key');
  res.setHeader('x-mcp-protocol-version', '2024-11-05'); 

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // 2. FORZAR ERROR 401 EN GET: Esto obliga a Claude a permitir la configuración manual por cabeceras
  if (req.method === 'GET') {
    return res.status(401).json({
      status: "unauthorized",
      message: "Se requiere autenticación mediante encabezados para conectar con este servidor MCP."
    });
  }

  // 3. Procesamiento del Protocolo MCP (POST)
  if (req.method === 'POST') {
    let body = {};
    
    try {
      if (typeof req.body === 'string') {
        body = JSON.parse(req.body);
      } else if (req.body) {
        body = req.body;
      }
    } catch (e) {
      return res.status(400).json({ error: "Cuerpo de petición JSON inválido" });
    }

    const { method, params, id } = body;

    // A. Listar herramientas
    if (method === "tools/list") {
      return res.status(200).json({
        jsonrpc: "2.0",
        id: id || 1,
        result: {
          tools: [
            {
              name: "shodan_search",
              description: "Busca dispositivos conectados a Internet en Shodan mediante una query de filtrado.",
              inputSchema: {
                type: "object",
                properties: {
                  query: {
                    type: "string",
                    description: "Filtros de búsqueda (ej: 'port:22', 'product:nginx', 'country:ES')."
                  },
                  limit: {
                    type: "number",
                    description: "Número máximo de resultados a retornar (Máx 20)."
                  }
                },
                required: ["query"]
              }
            }
          ]
        }
      });
    }

    // B. Ejecutar herramienta
    if (method === "tools/call") {
      const { name, arguments: args } = params || {};

      if (name === "shodan_search") {
        const query = args?.query;
        const requestedLimit = args?.limit;
        const apiKey = process.env.SHODAN_API_KEY;

        if (!apiKey) {
          return res.status(200).json({
            jsonrpc: "2.0",
            id: id || 1,
            result: { isError: true, content: [{ type: "text", text: "[Error] SHODAN_API_KEY no configurada en Vercel." }] }
          });
        }

        if (!query) {
          return res.status(200).json({
            jsonrpc: "2.0",
            id: id || 1,
            result: { isError: true, content: [{ type: "text", text: "[Error] Falta el argumento 'query'." }] }
          });
        }

        const limit = requestedLimit ? Math.min(Math.max(requestedLimit, 1), 20) : 5;

        try {
          const shodanUrl = new URL('https://shodan.io');
          shodanUrl.searchParams.append('key', apiKey);
          shodanUrl.searchParams.append('query', query);
          shodanUrl.searchParams.append('page', '1');

          const response = await fetch(shodanUrl.toString());
          const data = await response.json();

          if (!response.ok) {
            return res.status(200).json({
              jsonrpc: "2.0",
              id: id || 1,
              result: { isError: true, content: [{ type: "text", text: `Shodan Error: ${data.error || response.statusText}` }] }
            });
          }

          const matches = Array.isArray(data.matches) ? data.matches : [];
          const cleanResults = matches.slice(0, limit).map(host => ({
            ip: host.ip_str || null,
            port: host.port || null,
            isp: host.isp || null,
            org: host.org || null,
            country: host.location?.country_name || null,
            product: host.product || null,
            vulns: Array.isArray(host.vulns) ? host.vulns.slice(0, 5) : []
          }));

          return res.status(200).json({
            jsonrpc: "2.0",
            id: id || 1,
            result: {
              content: [
                {
                  type: "text",
                  text: JSON.stringify({ total: data.total || 0, results: cleanResults }, null, 2)
                }
              ]
            }
          });

        } catch (error) {
          return res.status(200).json({
            jsonrpc: "2.0",
            id: id || 1,
            result: { isError: true, content: [{ type: "text", text: `Error: ${error.message}` }] }
          });
        }
      }
    }

    return res.status(200).json({
      jsonrpc: "2.0",
      id: id || 1,
      error: { code: -32601, message: "Método no implementado." }
    });
  }

  return res.status(405).json({ error: "Método no permitido" });
}
