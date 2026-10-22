export default async function handler(req, res) {
  // 1. Configuración estricta de CORS requerida por Claude
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-mcp-protocol-version');

  // Responder a peticiones preflight de CORS
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // 2. Endpoint de salud / Conexión básica (GET)
  if (req.method === 'GET') {
    return res.status(200).json({
      status: "active",
      protocol: "MCP",
      description: "Servidor MCP para Shodan en Vercel"
    });
  }

  // 3. Procesamiento del Protocolo MCP (POST)
  if (req.method === 'POST') {
    const { method, params, id } = req.body || {};

    // PASO A: Claude solicita la lista de herramientas disponibles
    if (method === "tools/list") {
      return res.status(200).json({
        jsonrpc: "2.0",
        id,
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
                    description: "Términos de búsqueda o filtros (ej: 'port:22', 'product:nginx', 'country:ES')."
                  },
                  limit: {
                    type: "number",
                    description: "Número máximo de hosts a retornar (Por defecto 5, Máximo 20)."
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

        // Validaciones iniciales
        if (!apiKey) {
          return res.status(200).json({
            jsonrpc: "2.0",
            id,
            result: {
              isError: true,
              content: [{ type: "text", text: "[Error] La variable de entorno SHODAN_API_KEY no está configurada en Vercel." }]
            }
          });
        }

        if (!query) {
          return res.status(200).json({
            jsonrpc: "2.0",
            id,
            result: {
              isError: true,
              content: [{ type: "text", text: "[Error] No se ha proporcionado el argumento requerido: query." }]
            }
          });
        }

        const limit = requestedLimit ? Math.min(Math.max(requestedLimit, 1), 20) : 5;

        try {
          // Consulta directa a la API de Shodan
          const shodanUrl = new URL('https://shodan.io');
          shodanUrl.searchParams.append('key', apiKey);
          shodanUrl.searchParams.append('query', query);
          shodanUrl.searchParams.append('page', '1');

          const response = await fetch(shodanUrl.toString());
          
          if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            return res.status(200).json({
              jsonrpc: "2.0",
              id,
              result: {
                isError: true,
                content: [{ type: "text", text: `Shodan respondió con error: ${errData.error || response.statusText}` }]
              }
            });
          }

          const data = await response.json();
          const matches = Array.isArray(data.matches) ? data.matches : [];

          // Simplificar y estructurar los datos para no saturar el contexto de Claude
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

          // Respuesta final exitosa bajo el formato estricto de MCP
          return res.status(200).json({
            jsonrpc: "2.0",
            id,
            result: {
              content: [
                {
                  type: "text",
                  text: JSON.stringify({
                    info: `Mostrando ${cleanResults.length} de ${data.total || 0} resultados totales encontrados.`,
                    results: cleanResults
                  }, null, 2)
                }
              ]
            }
          });

        } catch (error) {
          return res.status(200).json({
            jsonrpc: "2.0",
            id,
            result: {
              isError: true,
              content: [{ type: "text", text: `Error interno de ejecución en el Proxy: ${error.message}` }]
            }
          });
        }
      }
    }

    // Manejo de métodos JSON-RPC no soportados
    return res.status(200).json({
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: "Método MCP no implementado en este conector." }
    });
  }

  // Rechazar cualquier otro método HTTP distinto de GET, POST u OPTIONS
  return res.status(405).json({ error: "Método HTTP no permitido" });
