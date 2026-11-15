"""在原应用握手之后叠加用户显式批准的 Linux 服务，仅授予显式批准的工具。"""
from dataclasses import replace
from .application_platform import ApplicationPlatform


class LinuxApplicationPlatform(ApplicationPlatform):
    def __init__(self,runtime,services,**kwargs):
        self.services=services
        super().__init__(runtime,**kwargs)

    def prepare(self,connection,request):
        owner,binding=super().prepare(connection,request)
        if owner is not None:
            with self.lock,self.runtime.control.apps.lock:
                policy=self.runtime.policies[owner]
                grants=self.services.grants(owner)
                base=policy.tools-frozenset(self.services.schema)
                self.runtime.policies[owner]=replace(policy,tools=base|grants,
                    methods=policy.methods|({'submit'} if grants else set()),
                    max_calls=max(policy.max_calls or 0,1000) if grants else policy.max_calls)
                scope=self.runtime.work_scope or frozenset()
                # 保留曾授权的队列范围，让撤销后的旧任务被认领并明确拒绝。
                self.runtime.work_scope=scope|{(owner,name) for name in grants}
        return owner,binding
