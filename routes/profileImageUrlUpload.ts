/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateOrLoopback(hostname: string): boolean {
  const host = hostname.toLowerCase().trim();

  // 1. Check for localhost/local domains
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.localhost')) {
    return true;
  }

  // 2. IPv4 Checks
  const ipv4Regex = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
  const match4 = host.match(ipv4Regex);
  if (match4) {
    const octets = match4.slice(1).map(x => parseInt(x, 10));
    if (octets.some(o => o > 255)) {
      return true; // invalid IP, block it to be safe
    }
    const [o1, o2, o3, o4] = octets;
    if (o1 === 127) return true;
    if (o1 === 10) return true;
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;
    if (o1 === 192 && o2 === 168) return true;
    if (o1 === 169 && o2 === 254) return true;
    if (o1 === 0) return true;
  }

  // 3. IPv6 Checks
  if (host === '::1' || host === '0:0:0:0:0:0:0:1') {
    return true;
  }
  const cleanHost = host.replace(/^\[|\]$/g, '');
  if (cleanHost === '::1' || cleanHost === '0:0:0:0:0:0:0:1' || cleanHost === '::' || cleanHost === '0:0:0:0:0:0:0:0') {
    return true;
  }
  if (cleanHost.startsWith('fc') || cleanHost.startsWith('fd')) {
    return true;
  }
  if (cleanHost.startsWith('fe8') || cleanHost.startsWith('fe9') || cleanHost.startsWith('fea') || cleanHost.startsWith('feb')) {
    return true;
  }
  if (cleanHost.startsWith('::ffff:')) {
    const ipv4Part = cleanHost.substring(7);
    if (isPrivateOrLoopback(ipv4Part)) {
      return true;
    }
  }

  // Reject entirely numeric hostnames (e.g., dword IP or decimal IP)
  if (/^\d+$/.test(host)) {
    return true;
  }
  // Reject hexadecimal hostnames (e.g. 0x7f000001)
  if (/^0x[0-9a-f]+$/i.test(host)) {
    return true;
  }

  return false;
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (typeof url !== 'string') {
        next(new Error('Blocked illegal activity'))
        return
      }
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        let isSsrfAttempt = false
        try {
          const parsedUrl = new URL(url)
          if (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') {
            if (isPrivateOrLoopback(parsedUrl.hostname)) {
              isSsrfAttempt = true
            }
          } else {
            isSsrfAttempt = true
          }
        } catch (err) {
          // If URL parsing fails, it's not a valid remote HTTP/HTTPS URL and cannot cause SSRF
        }

        if (isSsrfAttempt) {
          next(new Error('Blocked illegal activity'))
          return
        }

        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
