/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''

      if (!isSafeOrderLines(orderLinesData)) {
        res.status(400)
        return next(new Error('Sanity check failed: Invalid orderLinesData.'))
      }

      try {
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}

function isSafeOrderLines (data: string): boolean {
  if (data.includes('\\')) {
    return false
  }
  if (/([a-zA-Z0-9_$)\]\}'"{\/])\s*\[/.test(data)) {
    return false
  }
  const forbiddenKeywords = [
    /\bconstructor\b/i,
    /\bprototype\b/i,
    /\b__proto__\b/i,
    /\bprocess\b/i,
    /\brequire\b/i,
    /\bexec\b/i,
    /\bexecSync\b/i,
    /\bspawn\b/i,
    /\bchild_process\b/i,
    /\bglobal\b/i,
    /\bglobalThis\b/i,
    /\bmainModule\b/i,
    /\bFunction\b/i,
    /\beval\b/i,
    /\bimport\b/i,
    /\bmodule\b/i,
    /\bsetTimeout\b/i,
    /\bsetInterval\b/i
  ]
  for (const pattern of forbiddenKeywords) {
    if (pattern.test(data)) {
      return false
    }
  }
  return true
}
