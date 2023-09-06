import { Command, Context, Dict, Primary, Schema } from 'koishi'

declare module 'koishi' {

  interface Tables {
    permissions: PermissionGroup
  }
}

interface PermissionGroup {
  id: Primary
  name: string
  permissions: string[]
}

function parsePlatform(target: string): [platform: string, id: string] {
  const index = target.indexOf(':')
  const platform = target.slice(0, index)
  const id = target.slice(index + 1)
  return [platform, id] as any
}

export class Permissions {
  disposables: Dict<() => void> = {}

  constructor(public ctx: Context, config: Permissions.Config) {
    ctx.i18n.define('zh', require('./locales/zh.yml'))

    ctx.model.extend('permissions', {
      id: 'primary',
      name: 'string',
      permissions: 'list',
    }, {
      autoInc: true,
    })

    function inheritPermissions(command: Command) {
      command[Context.current] = ctx
      if (command.parent) {
        command._disposables.push(
          ctx.permissions.depend(`command.${command.name}`, `command.${command.parent.name}`),
        )
      }
    }

    ctx.$commander._commandList.forEach(inheritPermissions)
    ctx.on('command-added', inheritPermissions)

    ctx.command('perm <...perms:string>')
      .option('user', '-u <user:user>')
      .option('currentUser', '-U')
      .option('channel', '-c <channel:channel>')
      .option('currentChannel', '-C')
      .option('group', '-g <group:string>')
      .option('delete', '-d')
      .action(async ({ session, options }, ...perms) => {
        console.log(options)
        if (options.delete && options.group && !perms.length) {
          await this.deleteGroup(`group.${options.group}`)
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
      const group = (await this.ctx.database.get('permissions', { name: target }))?.[0]
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
      const group = (await this.ctx.database.get('permissions', { name: target }))?.[0]
        ?? (await this.ctx.database.create('permissions', { name: target }))
      const permissions = new Set(group.permissions)
      set.forEach(permissions.add.bind(permissions))
      unset.forEach(permissions.delete.bind(permissions))
      await this.ctx.database.set('permissions', { name: target }, { permissions: [...permissions] })
      await this.#updateGroup(target, [...permissions])
    }
    return true
  }

  async deleteGroup(name: string) {
    await this.ctx.database.remove('permissions', { name })
    this.disposables[name]?.()
    delete this.disposables[name]
  }

  async #updateGroup(name: string, permissions?: string[]) {
    if (!permissions) {
      permissions = (await this.ctx.database.get('permissions', { name }))?.[0]?.permissions
    }
    if (!permissions) return
    this.disposables[name]?.()
    this.disposables[name] = this.ctx.permissions.define(name, permissions)
  }
}

export namespace Permissions {
  export const using = ['database']

  export interface Config {}

  export const Config: Schema<Config> = Schema.object({})
}

export default Permissions
