import hashlib
import os
import importlib
import inspect
import asyncio
import logging
import sqlite3
from cryptography.fernet import Fernet
import psutil
import aioconsole  # 引入异步控制台输入
import multiprocessing
from multiprocessing import Process, Queue
import shutil  # 用于文件操作

# 设置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 生成密钥并初始化 Fernet 对象用于加密
key = Fernet.generate_key()
cipher_suite = Fernet(key)

class PluginInterface:
    def __init__(self, config=None):
        self.config = config or {}
        self.state = '未加载'  # 插件状态

    async def load(self):
        self.state = '加载中'
        # 加载逻辑
        self.state = '已加载'

    async def unload(self):
        self.state = '卸载中'
        # 卸载逻辑
        self.state = '未加载'

    async def start(self):
        if self.state == '已加载':
            self.state = '启动中'
            # 启动逻辑
            self.state = '运行中'

    async def stop(self):
        if self.state == '运行中':
            self.state = '停止中'
            # 停止逻辑
            self.state = '已停止'

class PluginManager:
    def __init__(self, plugin_dir, db_path, max_plugins=5):
        self.plugin_dir = plugin_dir
        self.db_path = db_path
        self.plugins = {}  # 存储插件实例和相关信息
        self.extension_plugins = {}  # 存储扩展插件实例
        self.overlimit_mode = False
        self.resource_threshold = 80  # CPU或内存使用率的阈值
        self.max_plugins = max_plugins
        self.create_database()  # 创建数据库和表
        self.resource_semaphore = asyncio.Semaphore(max_plugins)  # 初始化信号量
        self.event_semaphore = asyncio.Semaphore(1)  # 事件信号量
        self.plugin_processes = {}  # 存储插件进程信息
        self.message_queue = Queue()  # 消息队列
        self.event_subscriptions = {}  # 事件订阅信息
        self.concurrent_tasks_semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self.event_batch_size = event_batch_size
        self.event_batch = {}

    def run(self):
        # 在子进程中运行插件
        try:
            asyncio.run(self.plugin_instance.start())
        except Exception as e:
            logging.error(f"插件 {self.plugin_name} 在子进程中运行时发生错误: {e}")

    def create_database(self):
        # 创建数据库和表
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS plugins (
                name TEXT PRIMARY KEY,
                install_time TEXT,
                hash TEXT,
                is_enabled INTEGER DEFAULT 1  -- 添加这一行以创建'is_enabled'列
            )
        ''')
        conn.commit()
        conn.close()

    def calculate_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def verify_plugin_integrity(self, plugin_name):
        plugin_path = os.path.join(self.plugin_dir, plugin_name + ".py")
        calculated_hash = self.calculate_hash(plugin_path)
        encrypted_hash = cipher_suite.encrypt(calculated_hash.encode())

        try:
            # 使用上下文管理器确保数据库连接正确关闭
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # 查询插件哈希值
                cursor.execute('SELECT hash FROM plugins WHERE name=?', (plugin_name,))
                stored_hash_row = cursor.fetchone()
            
                # 如果存在存储的哈希值，则进行解密和比较
                if stored_hash_row:
                    stored_hash = cipher_suite.decrypt(stored_hash_row[0]).decode()
                    return calculated_hash == stored_hash
                else:
                    # 如果没有找到存储的哈希值，则验证失败
                    return False
        except sqlite3.DatabaseError as e:
            logging.error(f"数据库操作失败: {e}")
            return False

    async def load_plugin_async(self, plugin_name, config=None):
        try:
            async with self.resource_semaphore:
                if plugin_name in self.plugins:
                    logging.info(f"插件 {plugin_name} 已经加载。")
                    return True

                if self.verify_plugin_integrity(plugin_name):
                    try:
                        plugin_module = importlib.import_module(plugin_name)
                        for name, obj in inspect.getmembers(plugin_module):
                            if inspect.isclass(obj) and issubclass(obj, PluginInterface) and obj is not PluginInterface:
                                # 创建一个进程间通信的队列
                                queue = Queue()
                                # 创建一个新进程来运行插件
                                plugin_process = Process(target=self.run_plugin, args=(obj, config, queue))
                                plugin_process.start()
                                
                                # 将插件实例和进程信息存储起来
                                self.plugins[plugin_name] = {
                                    'instance': obj(config=config),
                                    'process': plugin_process,
                                    'queue': queue
                                }
                                logging.info(f"插件 {plugin_name} 已成功加载并在新进程中运行。")
                                return True
                    except ImportError as e:
                        logging.error(f"加载插件 {plugin_name} 失败: 模块未找到。")
                    except Exception as e:
                        logging.error(f"加载插件 {plugin_name} 时发生错误: {e}")
                else:
                    logging.error(f"插件 {plugin_name} 完整性验证失败，拒绝加载。")
                return False
        except Exception as e:
            logging.error(f"加载插件 {plugin_name} 时发生未知错误: {e}")
            
    def run_plugin(self, plugin_class, config, queue):
        # 在新进程中运行插件
        plugin_instance = plugin_class(config=config)
        await plugin_instance.load()
        # 在插件运行结束后，发送一个消息到队列，通知主进程插件已卸载
        queue.put(f"{plugin_instance} has been unloaded.")

    async def unload_plugin_async(self, plugin_name):
        plugin_instance = None
        plugin_process = None
        plugin_type = "插件"

        # 尝试从普通插件和扩展插件字典中获取插件实例和进程
        if plugin_name in self.plugins:
            plugin_info = self.plugins.pop(plugin_name)
            plugin_instance = plugin_info['instance']
            plugin_process = plugin_info['process']
        elif plugin_name in self.extension_plugins:
            plugin_instance = self.extension_plugins.pop(plugin_name)
            plugin_type = "扩展插件"

        # 如果插件实例存在，则尝试卸载
        if plugin_instance:
            try:
                # 对于普通插件，我们需要在进程中卸载
                if plugin_process:
                    # 请求插件卸载
                    await plugin_instance.unload()  # 注意：这里不再使用 asyncio.run，因为已经在异步上下文中
                    # 等待插件进程结束
                    plugin_process.join()
                    logging.info(f"{plugin_type} {plugin_name} 进程已结束。")
                
                # 对于扩展插件，直接在当前上下文中卸载
                else:
                    await plugin_instance.unload()
                
                logging.info(f"{plugin_type} {plugin_name} 已成功卸载。")
                return True
            except Exception as e:
                logging.error(f"卸载 {plugin_type} {plugin_name} 时发生错误: {e}")
                # 出现异常时，将插件实例重新添加到字典中
                if plugin_type == "扩展插件":
                    self.extension_plugins[plugin_name] = plugin_instance
                else:
                    self.plugins[plugin_name] = {'instance': plugin_instance, 'process': plugin_process}
                return False
        else:
            logging.warning(f"{plugin_type} {plugin_name} 未找到，无法卸载。")
            return False

    async def use_resource(self, plugin_name, resource_action):
        try:
            async with self.resource_semaphore:
                await resource_action()
                logging.info(f"插件 {plugin_name} 成功使用了公共资源。")
        except Exception as e:
            logging.error(f"插件 {plugin_name} 使用公共资源时发生错误: {e}")
            if self.overlimit_mode:
                logging.warning(f"当前处于超限模式，错误可能与此模式有关。")

    async def enable_overlimit_mode(self):
        user_confirmation = await aioconsole.ainput("是否启用超限模式以防止资源耗尽? (yes/no): ")
        if user_confirmation.strip().lower() == 'yes':
            self.overlimit_mode = True
            logging.warning("超限模式已启用。请注意系统资源使用。")
            return True
        else:
            logging.info("用户未确认，超限模式未启用。")
            return False

    def disable_overlimit_mode(self):
        self.overlimit_mode = False
        logging.info("超限模式已禁用。")

    async def check_system_resources(self):
        while True:
            # 只在必要时进行资源检查
            if not self.overlimit_mode_enabled:
                cpu_usage = psutil.cpu_percent(interval=1)
                memory_usage = psutil.virtual_memory().percent

                if cpu_usage > self.cpu_threshold or memory_usage > self.memory_threshold:
                    logging.warning("系统资源使用超过阈值。")
                    # 异步等待用户确认是否启用超限模式
                    await self.enable_overlimit_mode()

            await asyncio.sleep(self.check_interval)

    async def handle_event(self, event_name, event_action):
        async with self.event_semaphore:
            # 检查系统资源是否超过阈值，如果是，则启用超限模式
            if self.check_system_resources():
                self.enable_overlimit_mode()
                logging.warning(f"事件 {event_name} 被推迟，因为系统资源接近阈值。")
                return

            try:
                # 执行事件操作
                await event_action()
                logging.info(f"事件 {event_name} 已完成。")
            except Exception as e:
                # 处理其他未知类型的异常
                logging.error(f"事件 {event_name} 执行失败：{e}")
                # 根据异常类型和严重性决定是否需要禁用超限模式或其他操作

    def get_plugins_from_db(self, enabled_only=False):
        with sqlite3.connect(self.db_path) as conn:  # 使用上下文管理器来自动关闭连接
            cursor = conn.cursor()
            query = 'SELECT name FROM plugins'
            if enabled_only:
                query += ' WHERE is_enabled=1'
            cursor.execute(query)
            plugins = [row[0] for row in cursor.fetchall()]
        return plugins

    def get_all_plugins_from_db(self):
        return self.get_plugins_from_db()

    def get_enabled_plugins_from_db(self):
        return self.get_plugins_from_db(enabled_only=True)
     
    def backup_plugin(self, plugin_name):
        # 备份当前插件版本
        plugin_path = os.path.join(self.plugin_dir, plugin_name + ".py")
        backup_path = os.path.join(self.plugin_dir, f"{plugin_name}_backup.py")
        shutil.copyfile(plugin_path, backup_path)

    async def hot_update_plugin(self, plugin_name, new_plugin_path):
        # 热更新插件，包括版本回滚机制
        self.backup_plugin(plugin_name)
        try:
            # 卸载旧插件
            await self.unload_plugin_async(plugin_name)
            # 验证新插件的完整性
            new_plugin_hash = self.calculate_hash(new_plugin_path)
            if self.verify_plugin_integrity(plugin_name, new_plugin_hash):
                # 替换旧插件文件
                os.rename(new_plugin_path, os.path.join(self.plugin_dir, plugin_name + ".py"))
                # 加载新插件
                if await self.load_plugin_async(plugin_name):
                    logging.info(f"插件 {plugin_name} 已成功热更新。")
                else:
                    raise Exception(f"加载新插件 {plugin_name} 失败。")
            else:
                raise Exception(f"新插件 {plugin_name} 完整性验证未通过。")
        except Exception as e:
            logging.error(f"插件 {plugin_name} 热更新失败：{e}")
            # 回滚到备份版本
            backup_path = os.path.join(self.plugin_dir, f"{plugin_name}_backup.py")
            os.rename(backup_path, os.path.join(self.plugin_dir, plugin_name + ".py"))
            # 尝试重新加载备份插件
            await self.load_plugin_async(plugin_name)

    def record_plugin_state(self, plugin_name, state, hash_value):
        # 记录插件状态和哈希值到数据库
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE plugins SET state=?, hash=? WHERE name=?', (state, hash_value, plugin_name))
        conn.commit()
        conn.close()

    def recover_plugin_states(self, max_retries=3):
        # 恢复插件状态，限制恢复次数
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT name, state, hash FROM plugins')
        for plugin_name, state, hash_value in cursor.fetchall():
            if state in ["已加载", "运行中"]:
                retries = 0
                while retries < max_retries:
                    if self.verify_plugin_integrity(plugin_name, hash_value):
                        asyncio.run(self.load_plugin_async(plugin_name))
                        plugin_instance = self.plugins.get(plugin_name)
                        if plugin_instance and state == "运行中":
                            asyncio.run(plugin_instance.start())
                        break
                    else:
                        logging.warning(f"插件 {plugin_name} 哈希值不匹配，尝试重新加载。")
                        retries += 1
                        if retries == max_retries:
                            logging.error(f"插件 {plugin_name} 达到最大恢复次数，跳过恢复。")
        conn.close()
    
    async def use_resource(self, plugin_name, resource_action):
        try:
            async with self.resource_semaphore:
                await resource_action()
            log_message = f"插件 {plugin_name} 在超限模式下使用了公共资源。" if self.overlimit_mode else f"插件 {plugin_name} 成功使用了公共资源。"
            logging.info(log_message)
        except Exception as e:
            log_message = f"插件 {plugin_name} 使用公共资源时发生错误: {e}"
            logging.error(log_message)
    
    async def publish_event(self, event_name, event_data):
        # 异步发布事件到消息队列
        await self.message_queue.put((event_name, event_data))

    def subscribe_to_event(self, event_name, plugin_instance):
        # 插件订阅事件
        if event_name not in self.event_subscriptions:
            self.event_subscriptions[event_name] = []
        self.event_subscriptions[event_name].append(plugin_instance)

    def unsubscribe_from_event(self, event_name, plugin_instance):
        # 插件取消订阅事件
        if event_name in self.event_subscriptions:
            if plugin_instance in self.event_subscriptions[event_name]:
                self.event_subscriptions[event_name].remove(plugin_instance)
            if not self.event_subscriptions[event_name]:
                del self.event_subscriptions[event_name]

    async def handle_event_in_plugin(self, plugin_instance, event_data):
        try:
            # 设置插件处理事件的超时时间
            await asyncio.wait_for(plugin_instance.handle_event(event_data), timeout=30.0)
        except asyncio.TimeoutError:
            logging.error(f"Plugin {plugin_instance} timed out handling event.")
        except Exception as e:
            logging.error(f"Error handling event in plugin {plugin_instance}: {e}")
        finally:
            self.concurrent_tasks_semaphore.release()

    async def event_dispatcher(self):
        while True:
            event_name, event_data = await self.message_queue.get()
            if event_name in self.event_subscriptions:
                # 批处理事件
                self.event_batch.setdefault(event_name, []).append(event_data)
                if len(self.event_batch[event_name]) >= self.event_batch_size:
                    await self.dispatch_batch(event_name)

    async def dispatch_batch(self, event_name):
        for plugin_instance in self.event_subscriptions[event_name]:
            # 获取信号量
            await self.concurrent_tasks_semaphore.acquire()
            # 创建任务来处理事件批次，但不等待它完成
            asyncio.create_task(self.handle_event_in_plugin(plugin_instance, self.event_batch[event_name]))
        # 清空批次
        self.event_batch[event_name] = []
                      
class MyPlugin(PluginInterface):
    async def handle_event(self, event_data):
        # 异步处理事件
        try:
            # 实现事件处理逻辑
            # ...
            logging.info(f"Handling event with data: {event_data}")
        except asyncio.TimeoutError:
            # 处理超时异常
            logging.warning(f"Timeout while handling event for plugin {self}: {event_data}")
        except Exception as e:
            # 处理其他异常
            logging.error(f"Error in handle_event for plugin {self}: {e}")
            # 可以在这里添加资源清理代码
        finally:
            # 在这里执行必要的清理工作，无论是否发生异常
            logging.info(f"Event handling completed for plugin {self}")

    async def handle_event_with_timeout(self, event_data, timeout):
        try:
            # 使用 asyncio.wait_for 设置超时
            await asyncio.wait_for(self.handle_event(event_data), timeout)
        except asyncio.TimeoutError:
            logging.error(f"Event handling timed out for plugin {self} after {timeout} seconds")
                      
async def main():
    plugin_dir = 'path_to_plugin_directory'  # 插件目录路径
    db_path = 'path_to_database'  # 数据库路径
    max_plugins = 5  # 最大插件数量

    plugin_manager = PluginManager(plugin_dir, db_path, max_plugins)

    # 恢复插件状态
    plugin_manager.recover_plugin_states()

    # 启动事件分发器任务
    event_dispatcher_task = asyncio.create_task(plugin_manager.event_dispatcher())

    # 启动资源监控任务
    resource_monitor_task = asyncio.create_task(plugin_manager.check_system_resources())

    try:
        # 等待资源监控任务启动
        await asyncio.sleep(1)

        # 加载所有启用的插件
        enabled_plugins = plugin_manager.get_enabled_plugins_from_db()
        for plugin_name in enabled_plugins:
            await plugin_manager.load_plugin_async(plugin_name)

        # 保持主循环运行，直到收到中断信号
        while True:
            await asyncio.sleep(1)  # 每秒检查一次，可以根据需要调整

    except asyncio.CancelledError:
        # 资源监控任务被取消
        pass
    except KeyboardInterrupt:
        logging.info("程序被用户中断。开始卸载插件...")
    except Exception as e:
        logging.error(f"主程序异常：{e}")
    finally:
        # 取消资源监控任务
        resource_monitor_task.cancel()

        # 卸载所有插件
        for plugin_name in list(plugin_manager.plugins.keys()):
            await plugin_manager.unload_plugin_async(plugin_name)

        # 取消事件分发器任务
        event_dispatcher_task.cancel()

        # 等待任务取消
        await asyncio.gather(resource_monitor_task, event_dispatcher_task, return_exceptions=True)

        # 关闭事件循环
        await asyncio.sleep(0)  # 确保所有任务都已取消
        asyncio.get_event_loop().shutdown_asyncgens()
        asyncio.get_event_loop().close()
        logging.info("程序已退出。")

if __name__ == "__main__":
    asyncio.run(main())
