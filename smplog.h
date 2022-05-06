/**
* Author: HBW
* Email: hackerhuang@qq.com
* Description: Simple Logging Tool
*/

#ifndef _SMPSYNCLOG_H_
#define _SMPSYNCLOG_H_

#pragma once

#include <string>
#include <vector>

#define ENABLE_LOG 1

namespace smplog{
	static const char* MAIN_LOGGER = "_ROOT_";
}

#define LEVEL_DEBUG smplog::SMPLOGLEVEL::DBG
#define LEVEL_INFO smplog::SMPLOGLEVEL::INFO
#define LEVEL_WARN smplog::SMPLOGLEVEL::WARN
#define LEVEL_ERROR smplog::SMPLOGLEVEL::ERR
#define LEVEL_FATAL smplog::SMPLOGLEVEL::FATAL

#define get_current_datetime_log smplog::get_datetime_log_name()

#if ENABLE_LOG
#define LOG_DEBUG(...) smplog::TraceLog(smplog::MAIN_LOGGER, smplog::SMPLOGLEVEL::DBG, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...) smplog::TraceLog(smplog::MAIN_LOGGER, smplog::SMPLOGLEVEL::INFO, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...) smplog::TraceLog(smplog::MAIN_LOGGER, smplog::SMPLOGLEVEL::WARN, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) smplog::TraceLog(smplog::MAIN_LOGGER, smplog::SMPLOGLEVEL::ERR, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define LOG_FATAL(...) smplog::TraceLog(smplog::MAIN_LOGGER, smplog::SMPLOGLEVEL::FATAL, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define LOG_iDEBUG(pcszLoggerName, ...) smplog::TraceLog(pcszLoggerName, smplog::SMPLOGLEVEL::DBG, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define LOG_iINFO(pcszLoggerName, ...) smplog::TraceLog(pcszLoggerName, smplog::SMPLOGLEVEL::INFO, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define LOG_iWARN(pcszLoggerName, ...) smplog::TraceLog(pcszLoggerName, smplog::SMPLOGLEVEL::WARN, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define LOG_iERROR(pcszLoggerName, ...) smplog::TraceLog(pcszLoggerName, smplog::SMPLOGLEVEL::ERR, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define LOG_iFATAL(pcszLoggerName, ...) smplog::TraceLog(pcszLoggerName, smplog::SMPLOGLEVEL::FATAL, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#else
#define LOG_DEBUG(...) ;
#define LOG_INFO(...) ;
#define LOG_WARN(...) ;
#define LOG_ERROR(...) ;
#define LOG_FATAL(...) ;

#define LOG_iDEBUG(...) ;
#define LOG_iINFO(...) ;
#define LOG_iWARN(...) ;
#define LOG_iERROR(...) ;
#define LOG_iFATAL(...) ;
#endif

namespace smplog{
	enum SMPLOGLEVEL
	{
		DBG,
		INFO,
		WARN,
		ERR,
		FATAL
	};

	std::string get_datetime_log_name();

	std::string get_datetime_log_post_name(const char *postFix);

	class BasicHandler
	{
	public:
		BasicHandler(SMPLOGLEVEL logLevel);
		virtual void write_log(
			const char *pcszTime,
			const char *pcszFilePath,
			const char *pcszFuncName,
			long lLine, SMPLOGLEVEL msgLevel,
			const char *pcszMessage
			) = 0;
	protected:
		std::string _build_message(
			const char *pcszTime,
			const char *pcszFilePath,
			const char *pcszFuncName,
			long lLine, SMPLOGLEVEL msgLevel,
			const char *pcszMessage
			);
		SMPLOGLEVEL m_logLevel;
	};

	class ConsoleHandler : public BasicHandler
	{
	public:
		ConsoleHandler(SMPLOGLEVEL logLevel);
		virtual void write_log(
			const char *pcszTime,
			const char *pcszFilePath,
			const char *pcszFuncName,
			long lLine, SMPLOGLEVEL msgLevel,
			const char *pcszMessage
			);
	};

	class FileHandler : public BasicHandler
	{
	public:
		FileHandler(const char* pcszLogFile, SMPLOGLEVEL logLevel);
		~FileHandler();
		virtual void write_log(
			const char *pcszTime,
			const char *pcszFilePath,
			const char *pcszFuncName,
			long lLine, SMPLOGLEVEL msgLevel,
			const char *pcszMessage
			);
		const char* get_file_path();
	protected:
		FILE *m_fp;
		const char* m_pcszLogFile;
	};

	class Logger
	{
	public:
		Logger(const std::string &strLoggerName);
		void append_handler(BasicHandler *pHdl);
		std::string name();
		void write_log(
			const char *pcszTime,
			const char *pcszFilePath,
			const char *pcszFuncName,
			long lLine, SMPLOGLEVEL msgLevel,
			const char *pcszMessage
			);
	private:
		std::vector<BasicHandler*> m_vecHdl;
		std::string m_strName;
	};

	class LogMgr
	{
	public:
		static LogMgr *get_log_instance();
		~LogMgr();
		void append_logger(std::string strLoggerName, BasicHandler *pHdl);
		void trace_log(
			std::string strLoggerName, SMPLOGLEVEL logLevel,
			const char* pcszFile, const char* pcszFunc,
			long lLine, const char* pcszMsgContent
			);
	private:
		LogMgr();
		std::vector<Logger*> m_vecLogger;
	};

	void AppendConsoleLog(SMPLOGLEVEL logOutputLevel);
	void AppendConsoleLog(const char* pcszLoggerName, SMPLOGLEVEL logOutputLevel);

	void AppendFileLog(const char* pcszFileLog, SMPLOGLEVEL logOutputLevel);
	void AppendFileLog(const char* pcszLoggerName, const char* pcszFileLog, SMPLOGLEVEL logOutputLevel);

	void TraceLog(const char* pcszLoggerName, SMPLOGLEVEL logLevel, const char* pcszFile, const char* pcszFunc, long lLine, const char* format, ...);


	std::string get_datetime_log_name();
}

#endif
