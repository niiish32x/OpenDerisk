'use client';

import { Button, Result } from 'antd';
import { useEffect } from 'react';

export default function ChatError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('Chat page error:', error);
  }, [error]);

  return (
    <div className="flex items-center justify-center h-full w-full">
      <Result
        status="error"
        title="页面加载异常"
        subTitle={error?.message || '渲染对话内容时发生错误，请重试'}
        extra={[
          <Button key="retry" type="primary" onClick={reset}>
            重试
          </Button>,
          <Button key="home" href="/chat">
            返回首页
          </Button>,
        ]}
      />
    </div>
  );
}
