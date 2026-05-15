"use client"
import { UserInfoResponse } from '@/types/userinfo';
import { STORAGE_USERINFO_KEY } from '@/utils/constants/index';
import { ChatContext } from '@/contexts';
import { authService } from '@/services/auth';
import { Avatar, Dropdown } from 'antd';
import { LogoutOutlined } from '@ant-design/icons';
import cls from 'classnames';
import { useContext, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

interface UserBarProps {
  onlyAvatar?: boolean;
}

function UserBar({ onlyAvatar = false }: UserBarProps) {
  const { t } = useTranslation();
  const { userInfo: contextUserInfo } = useContext(ChatContext);
  const [userInfo, setUserInfo] = useState<UserInfoResponse>();
  const [oauthEnabled, setOauthEnabled] = useState(false);

  useEffect(() => {
    const user = contextUserInfo ?? (() => {
      try {
        return JSON.parse(localStorage.getItem(STORAGE_USERINFO_KEY) ?? '') as UserInfoResponse;
      } catch {
        return undefined;
      }
    })();
    if (user) {
      setUserInfo(user);
      setOauthEnabled(!!user.user_channel);
    }
  }, [contextUserInfo]);

  const handleLogout = async () => {
    try {
      await authService.logout();
    } catch {
      /* ignore */
    }
    localStorage.removeItem(STORAGE_USERINFO_KEY);
    window.location.href = '/login';
  };

  const menuItems = oauthEnabled
    ? [
        {
          key: 'logout',
          icon: <LogoutOutlined />,
          label: t('logout') || '退出登录',
          onClick: handleLogout,
          danger: true,
        },
      ]
    : [];

  const avatarEl = (
    <Avatar
      src={userInfo?.avatar_url}
      className='bg-gradient-to-tr from-[#31afff] to-[#1677ff] cursor-pointer shrink-0'
    >
      {userInfo?.nick_name}
    </Avatar>
  );

  return (
    <div className={cls('flex flex-1 items-center', {
      'justify-center': onlyAvatar,
      'justify-start': !onlyAvatar,
    })}>
      <div
        className={cls('flex items-center group w-full', {
          'justify-center': onlyAvatar,
          'justify-start': !onlyAvatar,
        })}
      >
        <span className='flex gap-2 items-center overflow-hidden'>
          {oauthEnabled ? (
            <Dropdown menu={{ items: menuItems }} placement="topRight" trigger={['click']}>
              {avatarEl}
            </Dropdown>
          ) : (
            avatarEl
          )}
          <span
            className={cls('text-sm truncate font-medium text-gray-700 dark:text-gray-200', {
              hidden: onlyAvatar,
            })}
          >
            {userInfo?.nick_name}
          </span>
        </span>
      </div>
    </div>
  );
}

export default UserBar;
