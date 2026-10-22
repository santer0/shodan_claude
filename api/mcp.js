
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

function createServer() {
  const server = new McpServer({
    name: "shodan-claude",
    version: "1.0.0",
  });

  server.tool(
    "shodan_search",
    "Busca dispositivos conectados a Internet en Shodan mediante filtros como port:22, product:nginx o country:ES.",
    {
      query: z.string().min(1).describe("Consulta de búsqueda de Shodan"),
      limit: z.number().int().min(1).max(20).optional()
        .describe("Número máximo de resultados, entre 1 y 20"),
    },
    async ({ query, limit = 5 }) => {
      const apiKey = process.env.SHODAN_API_KEY;

      if (!apiKey) {
        return {
          isError: true,
          content: [{
            type: "text",
            text: "Falta configurar SHODAN_API_KEY en Vercel.",
          }],
        };
      }

      try {
        const url = new URL(
          "https://api.shodan.io/shodan/host/search"
        );

        url.searchParams.set("key", apiKey);
        url.searchParams.set("query", query);
        url.searchParams.set("page", "1");

        const response = await fetch(url);
        const data = await response.json();

        if (!response.ok) {
          return {
            isError: true,
            content: [{
              type: "text",
              text: `Shodan error (${response.status}): ${
                data.error || response.statusText
              }`,
            }],
          };
        }

        const results = (data.matches || [])
          .slice(0, limit)
          .map((host) => ({
            ip: host.ip_str || null,
            port: host.port || null,
            isp: host.isp || null,
            org: host.org || null,
            country: host.location?.country_name || null,
            product: host.product || null,
            vulns: Array.isArray(host.vulns)
              ? host.vulns.slice(0, 5)
              : [],
          }));

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              total: data.total || 0,
              results,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          isError: true,
          content: [{
            type: "text",
            text: `Error consultando Shodan: ${error.message}`,
          }],
        };
      }
    }
  );

  return server;
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, DELETE, OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    [
      "Content-Type",
      "Accept",
      "Authorization",
      "Mcp-Session-Id",
      "MCP-Protocol-Version",
      "Last-Event-ID",
    ].join(", ")
  );
  res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  // Este servidor es stateless y solo necesita peticiones POST.
  // GET no debe devolver un "OK" ficticio ni una página de login.
  if (req.method === "GET" || req.method === "DELETE") {
    res.setHeader("Allow", "POST, OPTIONS");
    return res.status(405).json({
      error: "Method not allowed",
    });
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    return res.status(405).json({
      error: "Method not allowed",
    });
  }

  let body = req.body;

  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      return res.status(400).json({
        error: "Invalid JSON",
      });
    }
  }

  if (!body || typeof body !== "object") {
    return res.status(400).json({
      error: "Invalid JSON-RPC request",
    });
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  try {
    const server = createServer();

    await server.connect(transport);

    await transport.handleRequest(req, res, body);
  } catch (error) {
    console.error("MCP error:", error);

    if (!res.headersSent) {
      return res.status(500).json({
        error: "Internal MCP server error",
      });
    }
  } finally {
    // En modo stateless, se libera la conexión al terminar la petición.
    // La respuesta ya enviada no debe modificarse.
    try {
      await transport.close();
    } catch {
      // No hay nada más que hacer si el transporte ya se cerró.
    }
  }
}
