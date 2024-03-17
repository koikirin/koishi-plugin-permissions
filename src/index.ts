import { Context, Schema } from 'koishi'
import { } from '@koishijs/plugin-admin'

function parsePlatform(target: string): [platform: string, id: string] {
  const index = target.indexOf(':')
  const platform = target.slice(0, index)
  const id = target.slice(index + 1)
  return [platform, id] as any
}

export class Permissions {
  constructor(public ctx: Context, config: Permissions.Config) {
    ctx.i18n.define('zh', require('./locales/zh'))

    config.builtinPermissions.forEach(
      perm => perm.enabled && perm.patterns.forEach(
        pattern => ctx.permissions.define(pattern, {
          depends: perm.depends,
          inherits: perm.inherits,
        }),
      ),
    )

    ctx.command('perm <...perms:string>', { authority: 3 })
      .option('user', '-u <user:user>')
      .option('currentUser', '-U')
      .option('channel', '-c <channel:channel>')
      .option('currentChannel', '-C')
      .option('group', '-g <group:string>')
      .option('delete', '-d')
      .action(async ({ session, options }, ...perms) => {
        if (options.delete && options.group && !perms.length) {
          const group = this.ctx.admin.groups.find(x => x.name === target)
          if (!group) return session.text('.notfound')
          await ctx.admin.deleteGroup(group.id)
          return session.text('.deleted')
        }

        const target = options.user ? `@${options.user}` : options.currentUser ? `#${session.uid}`
          : options.channel ? `#${options.channel}` : options.currentChannel ? `#${session.cid}`
            : options.group ? `group.${options.group}` : null
        if (!target) return session.execute('perm -h')
        if (perms.length) {
          const set = perms.filter(x => !x.startsWith('~'))
          const unset = perms.filter(x => x.startsWith('~')).map(x => x.slice(1))
          if (set.some(x => !this.ctx.permissions.list().includes(x))) {
            return session.text('.unknown-permission')
          }
          if (await this.modifyPermission(target, set, unset)) {
            return session.text('.success')
          } else {
            return session.text('.failure')
          }
        } else {
          return session.text('.permissions', { target, permissions: await this.listPermission(target) })
        }
      })

    ctx.command('perm.list').action(() => {
      return ctx.permissions.list().join('\n')
    })
  }

  async listPermission(target: string) {
    if (!target) return
    if (target.startsWith('@')) {
      const user = await this.ctx.database.getUser(...parsePlatform(target.slice(1)))
      return user?.permissions
    } else if (target.startsWith('#')) {
      const channel = await this.ctx.database.getChannel(...parsePlatform(target.slice(1)))
      return channel?.permissions
    } else {
      const group = this.ctx.admin.groups.find(x => x.name === target)
      return group?.permissions
    }
  }

  async modifyPermission(target: string, set: string[], unset: string[]) {
    if (!target) return false
    if (target.startsWith('@')) {
      const user = (await this.ctx.database.getUser(...parsePlatform(target.slice(1))))
        ?? (await this.ctx.database.createUser(...parsePlatform(target.slice(1)), {}))
      const permissions = new Set(user.permissions)
      set.forEach(permissions.add.bind(permissions))
      unset.forEach(permissions.delete.bind(permissions))
      await this.ctx.database.set('user', user.id, { permissions: [...permissions] })
    } else if (target.startsWith('#')) {
      const channel = (await this.ctx.database.getChannel(...parsePlatform(target.slice(1))))
        ?? (await this.ctx.database.createChannel(...parsePlatform(target.slice(1)), {}))
      const permissions = new Set(channel.permissions)
      set.forEach(permissions.add.bind(permissions))
      unset.forEach(permissions.delete.bind(permissions))
      await this.ctx.database.set('channel',
        { platform: channel.platform, id: channel.id },
        { permissions: [...permissions] },
      )
    } else {
      let group = this.ctx.admin.groups.find(x => x.name === target)
      if (!group) {
        const id = await this.ctx.admin.createGroup(target)
        group = this.ctx.admin.groups.find(x => x.id === id)
      }
      const permissions = new Set(group.permissions)
      set.forEach(permissions.add.bind(permissions))
      unset.forEach(permissions.delete.bind(permissions))
      await this.ctx.admin.updateGroup(group.id, [...permissions])
    }
    return true
  }
}

export namespace Permissions {
  export const inject = ['database']

  export interface BuiltinPermOptions {
    patterns: string[]
    enabled: boolean
    depends?: string[]
    inherits?: string[]
  }

  export interface Config {
    builtinPermissions: BuiltinPermOptions[]
  }

  export const Config: Schema<Config> = Schema.object({
    builtinPermissions: Schema.array(Schema.object({
      patterns: Schema.array(String).role('table'),
      enabled: Schema.boolean().default(true),
      depends: Schema.array(String).role('table'),
      inherits: Schema.array(String).role('table'),
    })).default([]),
  })
}

export default Permissions
