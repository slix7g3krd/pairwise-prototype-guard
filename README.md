# pairwise-prototype-guard

前端组件库开放对象合并后，原型链污染就从配置项钻进运行时：`__proto__` 被当成普通键递归合并，能改写 `Object.prototype`；`constructor.prototype` 绕过只查 `__proto__` 的过滤；嵌套对象里同样的键没有被清掉；数组合并保留被污染的索引；`get_path` 能沿 `__proto__` 读到继承属性；深拷贝只复制可枚举字段，脏键却跟着进去；配置覆盖后所有新对象都带上恶意默认值；删除操作能删原型上的属性；序列化结果里脏键又被还原；错误日志把完整对象打出来。security/prototype_guard.py 是核心，tests/test_prototype_guard.py 15个红。要修的是：危险键拒绝；`constructor` 与 `prototype` 联合检查；递归清理；数组索引过滤；路径取值只走自有属性；深拷贝隔离原型；删除限制；序列化白名单；对象冻结；日志脱敏。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
