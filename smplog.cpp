#include "smplog.h"

#include <time.h>
#include <stdarg.h>

#include <mutex>
#include <algorithm>
#include <memory>

#if _WIN32
#include <io.h>
#include <Windows.h>
#pragma warning(disable:4996)
#elif __APPLE__
#include <sys/time.h>
#endif

namespace smplog{

	std::string get_current_time()
	{
		char buf[32] = { 0 };
#if _WIN32
		SYSTEMTIME st;
		GetLocalTime(&st);
		sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
			st.wYear, st.wMonth, st.wDay,
			st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
#elif __APPLE__
		struct timeval    tv;
		struct timezone   tz;
		struct tm         *p;

		gettimeofday(&tv, &tz);
		p = localtime(&tv.tv_sec);
		sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
			p->tm_year + 1900,
			p->tm_mon + 1,
			p->tm_mday,
			p->tm_hour,
			p->tm_min, p->tm_sec, tv.tv_usec / 1000);
#endif
		return buf;
	}

	std::string get_datetime_log_name()
	{
		return get_datetime_log_post_name("");
	}

	std::string get_datetime_log_post_name(const char *postFix)
	{
		time_t rawtime;
		time(&rawtime);
		struct tm *pLocalTime = localtime(&rawtime);
		char buf[32] = { 0 };
		sprintf(buf, "%d%02d%02d_%02d%02d%02d_%s.log",
			pLocalTime->tm_year + 1900,
			pLocalTime->tm_mon + 1,
			pLocalTime->tm_mday, pLocalTime->tm_hour,
			pLocalTime->tm_min, pLocalTime->tm_sec,
			postFix);
		return buf;
	}

	const char* get_level_desc(SMPLOGLEVEL level)
	{
		switch (level)
		{
		case SMPLOGLEVEL::DBG:
			return "DEBUG";
		case SMPLOGLEVEL::INFO:
			return "INFO";
		case SMPLOGLEVEL::WARN:
			return "WARN";
		case SMPLOGLEVEL::ERR:
			return "ERROR";
		default:
			return "FATAL";
		}
	}

	BasicHandler::BasicHandler(SMPLOGLEVEL logLevel) : m_logLevel(logLevel)
	{}

	std::string BasicHandler::_build_message(
		const char *pcszTime,
		const char *pcszFilePath,
		const char *pcszFuncName,
		long lLine, SMPLOGLEVEL msgLevel,
		const char *pcszMessage
		)
	{
		std::string ret(pcszTime);
		ret += " [";
		ret += get_level_desc(msgLevel);
		ret += "]: ";
		ret += pcszMessage;
		return ret;
	}

	ConsoleHandler::ConsoleHandler(SMPLOGLEVEL logLevel) : BasicHandler(logLevel)
	{}

	void ConsoleHandler::write_log(
		const char *pcszTime,
		const char *pcszFilePath,
		const char *pcszFuncName,
		long lLine, SMPLOGLEVEL msgLevel,
		const char *pcszMessage
		)
	{
		static std::mutex fomtx;
		if (msgLevel < m_logLevel)
			return;
		{
			std::lock_guard<std::mutex> lg(fomtx);
			printf("%s\n", _build_message(
				pcszTime, pcszFilePath, pcszFuncName, lLine, msgLevel, pcszMessage).c_str());
		}
	}

	FileHandler::FileHandler(const char* pcszLogFile, SMPLOGLEVEL logLevel) :
		BasicHandler(logLevel), m_fp(NULL), m_pcszLogFile(pcszLogFile)
	{
		m_fp = fopen(m_pcszLogFile, "w+");
	}

	FileHandler::~FileHandler()
	{
		if (m_fp)
		{
			fclose(m_fp);
			m_fp = NULL;
		}
	}

	void FileHandler::write_log(
		const char *pcszTime,
		const char *pcszFilePath,
		const char *pcszFuncName,
		long lLine, SMPLOGLEVEL msgLevel,
		const char *pcszMessage
		)
	{
		static std::mutex fomtx;
		if (msgLevel < m_logLevel)
			return;
		{
			std::lock_guard<std::mutex> lg(fomtx);
			fprintf(m_fp, "%s\n", _build_message(
				pcszTime, pcszFilePath, pcszFuncName, lLine, msgLevel, pcszMessage).c_str());
			fflush(m_fp);
		}

	}

	const char* FileHandler::get_file_path()
	{
		return m_pcszLogFile;
	}

	Logger::Logger(const std::string &strLoggerName) :m_strName(strLoggerName)
	{}

	void Logger::append_handler(BasicHandler *pHdl)
	{
		m_vecHdl.push_back(pHdl);
	}

	std::string Logger::name()
	{
		return m_strName;
	}

	void Logger::write_log(
		const char *pcszTime,
		const char *pcszFilePath,
		const char *pcszFuncName,
		long lLine, SMPLOGLEVEL msgLevel,
		const char *pcszMessage
		)
	{
		for (auto &pHdl : m_vecHdl)
		{
			pHdl->write_log(
				pcszTime, pcszFilePath,
				pcszFuncName, lLine,
				msgLevel, pcszMessage
				);
		}
	}

	LogMgr* LogMgr::get_log_instance()
	{
		static std::mutex sgtInst;
		static LogMgr* pself = nullptr;
		if (!pself)
		{
			std::lock_guard<std::mutex> lg(sgtInst);
			if (!pself)
				pself = new LogMgr();
		}
		return pself;
	}

	LogMgr::LogMgr()
	{}
	LogMgr::~LogMgr()
	{

	}
	void LogMgr::append_logger(std::string strLoggerName, BasicHandler *pHdl)
	{
		auto itLogger = std::find_if(m_vecLogger.begin(), m_vecLogger.end(), [&strLoggerName](Logger *plog) {
			return plog->name() == strLoggerName;
		});
		if (itLogger == m_vecLogger.end())
		{
			m_vecLogger.push_back(new Logger(strLoggerName));
			itLogger = std::find_if(m_vecLogger.begin(), m_vecLogger.end(), [&strLoggerName](Logger* plog) {
				return plog->name() == strLoggerName;
			});
		}
		if (pHdl)
		{
			(*itLogger)->append_handler(pHdl);
		}
	}
	void LogMgr::trace_log(
		std::string strLoggerName, SMPLOGLEVEL logLevel,
		const char* pcszFile, const char* pcszFunc,
		long lLine, const char* pcszMsgContent
		)
	{
		auto itLogger = std::find_if(m_vecLogger.begin(), m_vecLogger.end(), [&strLoggerName](Logger* plog) {
			return plog->name() == strLoggerName;
		});
		if (itLogger != m_vecLogger.end())
		{
			(*itLogger)->write_log(get_current_time().c_str(), pcszFile,
				pcszFunc, lLine, logLevel, pcszMsgContent
				);
		}
	}

	void AppendConsoleLog(SMPLOGLEVEL logOutputLevel)
	{
		AppendConsoleLog(MAIN_LOGGER, logOutputLevel);
	}

	void AppendConsoleLog(const char* pcszLoggerName, SMPLOGLEVEL logOutputLevel)
	{
		LogMgr::get_log_instance()->append_logger(pcszLoggerName, new ConsoleHandler(logOutputLevel));
	}

	void AppendFileLog(const char* pcszFileLog, SMPLOGLEVEL logOutputLevel)
	{
		AppendFileLog(MAIN_LOGGER, pcszFileLog, logOutputLevel);
	}

	void AppendFileLog(const char* pcszLoggerName, const char* pcszFileLog, SMPLOGLEVEL logOutputLevel)
	{
		LogMgr::get_log_instance()->append_logger(pcszLoggerName, new FileHandler(pcszFileLog, logOutputLevel));
	}

	void TraceLog(const char* pcszLoggerName, SMPLOGLEVEL msgLevel, const char* pcszFile, const char* pcszFunc, long lLine, const char* format, ...)
	{
		static const int BUFSIZE = 16 * 1024;
		static std::unique_ptr<char[]> s_log_buf(new char[BUFSIZE]);
		char* buf = s_log_buf.get();
		memset(buf, 0, BUFSIZE);
		va_list args;
		va_start(args, format);
		vsprintf(buf, format, args);
		va_end(args);
#if _DEBUG
		LogMgr::get_log_instance()->trace_log(pcszLoggerName, msgLevel, pcszFile, pcszFunc, lLine, buf);
#else
		LogMgr::get_log_instance()->trace_log(pcszLoggerName, msgLevel, "", pcszFunc, lLine, buf);
#endif
	}
}
