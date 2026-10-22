export default async function handler(req, res) {
  // 1. Configuración de CORS y cabeceras nativas MCP requeridas por Claude
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-mcp-protocol-version');
  // Especifica la versión del protocolo para que el validador de Claude sepa que es MCP
  res.setHeader('x-mcp-protocol-version', '2024-11-05'); 

  // Responder a peticiones preflight de CORS
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // 2. Endpoint de verificación inicial (GET) - Corregido para validación web
  if (req.method === 'GET') {
    return res.status(200).json({
      status: "active",
      protocol: "MCP",
      version: "2024-11-05",
      capabilities: {
        tools: {} // Indica a Claude que este servidor expone herramientas
      }
    });
  }

  // 3. Procesamiento del Protocolo MCP (POST)
  if (req.method === 'POST') {
    let body = {};
    
    // Forzar el parseo del JSON de forma segura pase lo que pase
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

    // PASO A: Claude solicita la lista de herramientas disponibles
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

    // PASO B: Claude ejecuta la herramienta seleccionada
    if (method === "tools/call") {
      const { name, arguments: args } = params || {};

      if (name === "shodan_search") {
        const query = args?.query;
        const requestedLimit = args?.limit;
        const apiKey = process.env.SHODAN_API_KEY;

        // Validaciones de seguridad internas
        if (!apiKey) {
          return res.status(200).json({
            jsonrpc: "2.0",
            id: id || 1,
            result: {
              isError: true,
              content: [{ type: "text", text: "[Error] La variable de entorno SHODAN_API_KEY no está configurada en Vercel." }]
            }
          });
        }

        if (!query) {
          return res.status(200).json({
            jsonrpc: "2.0",
            id: id || 1,
            result: {
              isError: true,
              content: [{ type: "text", text: "[Error] No se ha proporcionado el argumento requerido: query." }]
            }
          });
        }

        const limit = requestedLimit ? Math.min(Math.max(requestedLimit, 1), 20) : 5;

        try {
          // Consulta directa a la API oficial de Shodan
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
              result: {
                isError: true,
                content: [{ type: "text", text: `Shodan respondió con error: ${data.error || response.statusText}` }]
              }
            });
          }

          const matches = Array.isArray(data.matches) ? data.matches : [];
          
          // Limpiar la respuesta para ajustarse al contexto de Claude
          const cleanResults = matches.slice(0, limit).map(host => ({
            ip: host.ip_str || null,
            port: host.port || null,
            isp: host.isp || null,
            org: host.org || null,
            country: host.location?.country_name || null,
            city: host.location?.city || null,
            product: host.product || null,
            version: host.version || null,
            os: host.os || null,
            domains: host.domains || [],
            vulns: Array.isArray(host.vulns) ? host.vulns.slice(0, 5) : []
          }));

          // Formato de retorno estricto del protocolo MCP
          return res.status(200).json({
            jsonrpc: "2.0",
            id: id || 1,
            result: {
              content: [
                {
                  type: "text",
                  text: JSON.stringify({
                    info: `Mostrando ${cleanResults.length} de ${data.total || 0} resultados totales.`,
                    results: cleanResults
                  }, null, 2)
                }
              ]
            }
          });

        } catch (error) {
          return res.status(200).json({
            jsonrpc: "2.0",
            id: id || 1,
            result: {
              isError: true,
              content: [{ type: "text", text: `Error interno en el Proxy de Vercel: ${error.message}` }]
            }
          });
        }
      }
    }

    // Respuesta por defecto para métodos JSON-RPC desconocidos
    return res.status(200).json({
      jsonrpc: "2.0",
      id: id || 1,
      error: { code: -32601, message: "Método MCP no implementado en este conector." }
    });
  }

  // Si intentan usar otro método HTTP no permitido
  return res.status(405).json({ error: "Método HTTP no permitido" });
}
