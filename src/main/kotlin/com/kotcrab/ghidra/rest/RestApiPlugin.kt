package com.kotcrab.ghidra.rest

import com.kotcrab.ghidra.rest.mapper.*
import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import docking.tool.ToolConstants
import ghidra.MiscellaneousPluginPackage
import ghidra.app.plugin.GenericPluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import io.ktor.http.*
import io.ktor.serialization.jackson.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.plugins.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.apache.logging.log4j.LogManager

@Suppress("unused")
@PluginInfo(
  status = PluginStatus.RELEASED,
  packageName = MiscellaneousPluginPackage.NAME,
  category = GenericPluginCategoryNames.MISC,
  shortDescription = "Rest API Plugin",
  description = "This plugin adds read-only REST API to your Ghidra project."
)
class RestApiPlugin(tool: PluginTool) : ProgramPlugin(tool) {
  companion object {
    private const val PLUGIN_NAME = "RestApiPlugin"
    private const val DEFAULT_PORT = 18489
    private val logger = LogManager.getLogger(RestApiPlugin::class.java)
  }

  private object Env {
    const val API_PORT = "GHIDRA_REST_API_PORT"
  }

  private var serverPort: Int = 0
  private var startServer: DockingAction? = null
  private var stopServer: DockingAction? = null

  private var server: ApplicationEngine? = null

  private val bookmarkMapper = BookmarkMapper()
  private val dataTypeMapper = DataTypeMapper()
  private val functionMapper = FunctionMapper()
  private val memoryBlockMapper = MemoryBlockMapper()
  private val relocationMapper = RelocationMapper()
  private val symbolMapper = SymbolMapper()

  public override fun init() {
    super.init()
    serverPort = System.getenv()[Env.API_PORT]?.toIntOrNull() ?: DEFAULT_PORT
    startServer = createAction("Start Rest API Server", ::startServer)
    stopServer = createAction("Stop Rest API Server", ::stopServer)
  }

  override fun dispose() {
    super.dispose()
    stopServer()
  }

  private fun createAction(name: String, handler: () -> Unit): DockingAction {
    val action = object : DockingAction(name, PLUGIN_NAME) {
      override fun actionPerformed(context: ActionContext?) {
        handler()
      }
    }
    action.menuBarData = MenuData(arrayOf(ToolConstants.MENU_TOOLS, name))
    action.isEnabled = true
    tool.addAction(action)
    return action
  }

  private fun startServer() {
    server = createServer().also { it.start() }
  }

  private fun stopServer() {
    server?.stop()
    server = null
  }

  private fun createServer(): ApplicationEngine {
    return embeddedServer(CIO, port = serverPort) {
      configureServer()
    }
  }

  private fun Application.configureServer() {
    install(ContentNegotiation) {
      jackson()
    }
    install(StatusPages) {
      exception<BadRequestException> { call, cause ->
        call.respond(HttpStatusCode.BadRequest, mapOf("message" to cause.message))
      }
      exception<Throwable> { call, cause ->
        call.respond(HttpStatusCode.InternalServerError, mapOf("message" to cause.message))
      }
    }
    installRouting()
  }

  private fun Application.installRouting() = routing {
    route("/v1") {
      get("/bookmarks") {
        withErrorLogging {
          ensureProgramLoaded()
          val bookmarks = bookmarkMapper.map(currentProgram.bookmarkManager)
          call.respond(mapOf("bookmarks" to bookmarks))
        }
      }
      get("/memory") {
        withErrorLogging {
          ensureProgramLoaded()
          val address = call.request.queryParameters["address"]
            ?: throw BadRequestException("Address is required")
          val length = call.request.queryParameters["length"]?.decodeIntOrThrow()
            ?: throw BadRequestException("Length is required")
          val rawFormat = call.request.queryParameters["format"]?.equals("raw", ignoreCase = true) ?: false
          if (length <= 0) {
            throw BadRequestException("Length must be > 0")
          }
          val programAddress = currentProgram.addressFactory.getAddress(address)
            ?: throw BadRequestException("Invalid address")
          val result = runCatching {
            val result = ByteArray(length)
            val readBytes = currentProgram.memory.getBytes(programAddress, result)
            result.sliceArray(0..<readBytes)
          }
            .onFailure { throw BadRequestException("Can't read memory at $address", it) }
            .getOrThrow()
          if (rawFormat) {
            call.respondBytes(result, ContentType.Application.OctetStream)
          } else {
            call.respond(mapOf("memory" to result))
          }
        }
      }
      get("/memory-blocks") {
        withErrorLogging {
          ensureProgramLoaded()
          val memoryBlocks = memoryBlockMapper.map(currentProgram.memory)
          call.respond(mapOf("memoryBlocks" to memoryBlocks))
        }
      }
      get("/relocations") {
        withErrorLogging {
          ensureProgramLoaded()
          val relocations = relocationMapper.map(currentProgram.relocationTable)
          call.respond(mapOf("relocations" to relocations))
        }
      }
      get("/functions") {
        withErrorLogging {
          ensureProgramLoaded()
          val functions = functionMapper.map(currentProgram.functionManager)
          call.respond(mapOf("functions" to functions))
        }
      }
      get("/symbols") {
        withErrorLogging {
          ensureProgramLoaded()
          val symbols = symbolMapper.map(currentProgram.symbolTable, currentProgram.listing)
          call.respond(mapOf("symbols" to symbols))
        }
      }
      get("/types") {
        withErrorLogging {
          ensureProgramLoaded()
          val excludeUndefinedComponents = call.request.queryParameters["excludeUndefinedComponents"].toBoolean()
          val types = dataTypeMapper.map(currentProgram.dataTypeManager, excludeUndefinedComponents)
          call.respond(mapOf("types" to types))
        }
      }
    }
  }

  private fun String.decodeIntOrThrow(): Int {
    return runCatching { Integer.decode(this) }
      .getOrNull()
      ?: throw BadRequestException("Invalid number format")
  }

  private fun ensureProgramLoaded() {
    if (currentProgram == null) {
      throw BadRequestException("No program is loaded")
    }
  }

  private inline fun withErrorLogging(block: () -> Unit) {
    runCatching { block() }
      .onFailure { logger.error("Error in $PLUGIN_NAME: ${it.message}", it) }
      .getOrThrow()
  }
}
